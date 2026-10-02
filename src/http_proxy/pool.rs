use std::collections::HashSet;
use std::future::Future;
use std::io::BufReader;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::{http1, http2};
use hyper::header::HeaderName;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::debug;

use super::config::{TlsServerName, UpstreamConfig, UpstreamProtocol};
use crate::gateway::admission::RequestLease;
use crate::gateway::body::{self, BoxError, ResponseBody};

type RequestBody = ResponseBody;
trait UpstreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> UpstreamIo for T {}
type BoxIo = Box<dyn UpstreamIo>;

#[derive(Debug, thiserror::Error)]
#[error("HTTP upstream capacity reached")]
pub(crate) struct PoolOverload;

#[derive(Default)]
pub(crate) struct PoolCounters {
    pub(crate) opened: AtomicU64,
    pub(crate) reused: AtomicU64,
    pub(crate) rejected: AtomicU64,
}

pub(crate) struct UpstreamPool {
    pub(crate) config: UpstreamConfig,
    connector: Option<TlsConnector>,
    tls_name: Option<String>,
    connections: Arc<Semaphore>,
    global_connections: Arc<Semaphore>,
    active: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    connect_gate: Arc<Semaphore>,
    idle_http1: Mutex<Vec<(Instant, Http1Connection)>>,
    idle_available: Notify,
    http2: Mutex<Option<Http2Connection>>,
    last_activity: Mutex<Instant>,
    connect_timeout: Duration,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    pub(crate) counters: Arc<PoolCounters>,
}

pub(crate) struct ConnectionControl {
    cancellation: CancellationToken,
    _local: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

pub(crate) struct Http1Connection {
    pub(crate) sender: http1::SendRequest<RequestBody>,
    control: Arc<ConnectionControl>,
}
impl Drop for Http1Connection {
    fn drop(&mut self) {
        self.control.cancellation.cancel();
    }
}
struct Http2Connection {
    sender: http2::SendRequest<RequestBody>,
    control: Arc<ConnectionControl>,
}
impl Drop for Http2Connection {
    fn drop(&mut self) {
        self.control.cancellation.cancel();
    }
}

pub(crate) struct ExchangeLease {
    _active: OwnedSemaphorePermit,
    _admission: Option<Arc<RequestLease>>,
    upload_complete: AtomicBool,
    cancellation: CancellationToken,
}
impl ExchangeLease {
    pub(crate) fn cancel(&self) {
        self.cancellation.cancel();
    }
}

impl UpstreamPool {
    pub(crate) async fn new(
        config: UpstreamConfig,
        host: &str,
        global_connections: Arc<Semaphore>,
        connect_timeout: Duration,
        shutdown: CancellationToken,
        tasks: TaskTracker,
        counters: Arc<PoolCounters>,
    ) -> Result<Arc<Self>> {
        let tls_name = if config.tls {
            Some(match &config.tls_server_name {
                TlsServerName::RequestHost => host.to_owned(),
                TlsServerName::Literal(name) => name.clone(),
            })
        } else {
            None
        };
        let connector = if config.tls {
            let mut roots =
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(path) = &config.ca_file {
                let pem = tokio::fs::read(path)
                    .await
                    .with_context(|| format!("cannot read upstream CA {}", path.display()))?;
                let certs = rustls_pemfile::certs(&mut BufReader::new(pem.as_slice()))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let (added, ignored) = roots.add_parsable_certificates(certs);
                if added == 0 || ignored != 0 {
                    bail!("upstream CA file must contain usable certificates only");
                }
            }
            let mut tls =
                ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            tls.alpn_protocols = vec![match config.protocol {
                UpstreamProtocol::Http1 => b"http/1.1".to_vec(),
                UpstreamProtocol::Http2 => b"h2".to_vec(),
            }];
            Some(TlsConnector::from(Arc::new(tls)))
        } else {
            None
        };
        Ok(Arc::new(Self {
            connections: Arc::new(Semaphore::new(config.pool.max_connections)),
            active: Arc::new(Semaphore::new(config.pool.max_active_requests)),
            pending: Arc::new(Semaphore::new(config.pool.max_pending_requests)),
            connect_gate: Arc::new(Semaphore::new(1)),
            idle_http1: Mutex::new(Vec::new()),
            idle_available: Notify::new(),
            http2: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            config,
            connector,
            tls_name,
            global_connections,
            connect_timeout,
            shutdown,
            tasks,
            counters,
        }))
    }

    pub(crate) fn begin_exchange(
        &self,
        admission: Option<Arc<RequestLease>>,
        upload_complete: bool,
    ) -> Result<Arc<ExchangeLease>> {
        if self.shutdown.is_cancelled() {
            bail!("HTTP proxy shutting down");
        }
        let permit = Arc::clone(&self.active).try_acquire_owned().map_err(|_| {
            self.counters.rejected.fetch_add(1, Ordering::Relaxed);
            anyhow!(PoolOverload)
        })?;
        self.record_activity();
        Ok(Arc::new(ExchangeLease {
            _active: permit,
            _admission: admission,
            upload_complete: AtomicBool::new(upload_complete),
            cancellation: self.shutdown.child_token(),
        }))
    }

    /// A finite pending semaphore is acquired before any potentially queued capacity wait.
    async fn acquire_capacity(&self, capacity: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(capacity).try_acquire_owned() {
            return Ok(permit);
        }
        let _pending = Arc::clone(&self.pending)
            .try_acquire_owned()
            .map_err(|_| anyhow!(PoolOverload))?;
        tokio::select! {
            () = self.shutdown.cancelled() => Err(anyhow!("HTTP proxy shutting down")),
            result = timeout(self.config.pool.pending_timeout, Arc::clone(capacity).acquire_owned()) => {
                result.map_err(|_| anyhow!(PoolOverload))?.context("HTTP upstream capacity closed")
            }
        }
    }

    async fn connect(
        &self,
        reserved_local: Option<OwnedSemaphorePermit>,
    ) -> Result<(BoxIo, Arc<ConnectionControl>)> {
        let local = match reserved_local {
            Some(permit) => permit,
            None => self.acquire_capacity(&self.connections).await?,
        };
        let global = self.acquire_capacity(&self.global_connections).await?;
        let control = Arc::new(ConnectionControl {
            cancellation: self.shutdown.child_token(),
            _local: local,
            _global: global,
        });
        let connect = async {
            let tcp = TcpStream::connect(self.config.address).await?;
            tcp.set_nodelay(true)?;
            if let Some(connector) = &self.connector {
                let name = self.tls_name.clone().context("HTTPS upstream requires a TLS name")?;
                let tls = connector.connect(ServerName::try_from(name)?, tcp).await?;
                let alpn = tls.get_ref().1.alpn_protocol();
                if self.config.protocol == UpstreamProtocol::Http2 && alpn != Some(b"h2".as_slice())
                {
                    bail!("HTTP/2 TLS upstream did not negotiate h2");
                }
                Ok::<BoxIo, anyhow::Error>(Box::new(tls))
            } else {
                Ok(Box::new(tcp) as BoxIo)
            }
        };
        let io = tokio::select! {
            () = self.shutdown.cancelled() => return Err(anyhow!("HTTP proxy shutting down")),
            result = timeout(self.connect_timeout, connect) => result.context("HTTP upstream connect/TLS timeout")??,
        };
        self.counters.opened.fetch_add(1, Ordering::Relaxed);
        Ok((io, control))
    }

    fn take_idle_http1(&self) -> Result<Option<Http1Connection>> {
        let mut idle =
            self.idle_http1.lock().map_err(|_| anyhow!("HTTP/1 idle pool unavailable"))?;
        while let Some((since, connection)) = idle.pop() {
            if since.elapsed() < self.config.pool.idle_timeout && !connection.sender.is_closed() {
                self.counters.reused.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(connection));
            }
        }
        Ok(None)
    }

    pub(crate) async fn acquire_http1(&self) -> Result<Http1Connection> {
        if let Some(connection) = self.take_idle_http1()? {
            return Ok(connection);
        }
        let local = match Arc::clone(&self.connections).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let _pending = Arc::clone(&self.pending)
                    .try_acquire_owned()
                    .map_err(|_| anyhow!(PoolOverload))?;
                let wait = async {
                    loop {
                        // Register notification before examining the idle list to avoid lost wakeups.
                        let notified = self.idle_available.notified();
                        tokio::pin!(notified);
                        notified.as_mut().enable();
                        if let Some(connection) = self.take_idle_http1()? {
                            return Ok::<_, anyhow::Error>(Err(connection));
                        }
                        tokio::select! {
                            () = self.shutdown.cancelled() => return Err(anyhow!("HTTP proxy shutting down")),
                            () = &mut notified => {}
                            permit = Arc::clone(&self.connections).acquire_owned() => return Ok(Ok(permit.context("HTTP/1 connection capacity closed")?)),
                        }
                    }
                };
                match timeout(self.config.pool.pending_timeout, wait)
                    .await
                    .map_err(|_| anyhow!(PoolOverload))??
                {
                    Err(connection) => return Ok(connection),
                    Ok(permit) => permit,
                }
            }
        };
        let (io, control) = self.connect(Some(local)).await?;
        let (sender, connection) = timeout(
            self.connect_timeout,
            http1::Builder::new()
                .max_buf_size(32768)
                .handshake::<_, RequestBody>(TokioIo::new(io)),
        )
        .await
        .context("HTTP/1 upstream handshake timeout")??;
        let driver_control = Arc::clone(&control);
        let driver = self.tasks.spawn(async move {
            tokio::select! {
                () = driver_control.cancellation.cancelled() => {}
                result = connection.with_upgrades() => { if let Err(error) = result { debug!(%error, "HTTP/1 upstream driver closed"); } }
            }
        });
        drop(driver); // TaskTracker supervises shutdown and reclamation.
        Ok(Http1Connection { sender, control })
    }

    pub(crate) async fn wait_http1_ready(&self, connection: &mut Http1Connection) -> Result<()> {
        let _pending = if connection.sender.is_ready() {
            None
        } else {
            Some(
                Arc::clone(&self.pending)
                    .try_acquire_owned()
                    .map_err(|_| anyhow!(PoolOverload))?,
            )
        };
        timeout(self.config.pool.pending_timeout, connection.sender.ready())
            .await
            .map_err(|_| anyhow!(PoolOverload))?
            .context("HTTP/1 upstream is not ready")
    }

    pub(crate) async fn send_http2(
        &self,
        request: Request<RequestBody>,
    ) -> Result<(Response<Incoming>, Arc<ConnectionControl>)> {
        let (mut sender, control) = self.acquire_http2().await?;
        let _pending = if sender.is_ready() {
            None
        } else {
            Some(
                Arc::clone(&self.pending)
                    .try_acquire_owned()
                    .map_err(|_| anyhow!(PoolOverload))?,
            )
        };
        timeout(self.config.pool.pending_timeout, sender.ready())
            .await
            .map_err(|_| anyhow!(PoolOverload))?
            .context("HTTP/2 upstream is not ready")?;
        let response =
            sender.send_request(request).await.context("HTTP/2 upstream request failed")?;
        Ok((response, control))
    }

    async fn acquire_http2(
        &self,
    ) -> Result<(http2::SendRequest<RequestBody>, Arc<ConnectionControl>)> {
        if let Some(connection) = self.current_http2()? {
            self.counters.reused.fetch_add(1, Ordering::Relaxed);
            return Ok(connection);
        }
        // Only one connection establishment per pool; any wait has bounded pending capacity.
        let _gate = self.acquire_capacity(&self.connect_gate).await?;
        if let Some(connection) = self.current_http2()? {
            self.counters.reused.fetch_add(1, Ordering::Relaxed);
            return Ok(connection);
        }
        let (io, control) = self.connect(None).await?;
        let (sender, connection) = timeout(
            self.connect_timeout,
            http2::Builder::new(TokioExecutor::new())
                .max_send_buf_size(65536)
                .max_header_list_size(32768)
                .handshake::<_, RequestBody>(TokioIo::new(io)),
        )
        .await
        .context("HTTP/2 upstream handshake timeout")??;
        let driver_control = Arc::clone(&control);
        let driver = self.tasks.spawn(async move {
            tokio::select! {
                () = driver_control.cancellation.cancelled() => {}
                result = connection => { if let Err(error) = result { debug!(%error, "HTTP/2 upstream driver closed"); } }
            }
        });
        drop(driver);
        *self.http2.lock().map_err(|_| anyhow!("HTTP/2 pool unavailable"))? =
            Some(Http2Connection {
                sender: sender.clone(),
                control: Arc::clone(&control),
            });
        Ok((sender, control))
    }

    fn current_http2(
        &self,
    ) -> Result<Option<(http2::SendRequest<RequestBody>, Arc<ConnectionControl>)>> {
        let mut slot = self.http2.lock().map_err(|_| anyhow!("HTTP/2 pool unavailable"))?;
        if slot.as_ref().is_some_and(|connection| connection.sender.is_closed()) {
            slot.take();
        }
        Ok(slot
            .as_ref()
            .map(|connection| (connection.sender.clone(), Arc::clone(&connection.control))))
    }

    fn return_http1(&self, connection: Http1Connection) {
        self.record_activity();
        if self.shutdown.is_cancelled() || connection.sender.is_closed() {
            return;
        }
        if let Ok(mut idle) = self.idle_http1.lock()
            && idle.len() < self.config.pool.max_idle_connections
        {
            idle.push((Instant::now(), connection));
            self.idle_available.notify_one();
        }
    }
    fn record_activity(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }
    pub(crate) fn reap_idle(&self) {
        if let Ok(mut idle) = self.idle_http1.lock() {
            idle.retain(|(since, connection)| {
                !self.shutdown.is_cancelled()
                    && since.elapsed() < self.config.pool.idle_timeout
                    && !connection.sender.is_closed()
            });
        }
        let idle_expired = self
            .last_activity
            .lock()
            .map(|last| last.elapsed() >= self.config.pool.idle_timeout)
            .unwrap_or(false);
        if (self.shutdown.is_cancelled()
            || (self.active.available_permits() == self.config.pool.max_active_requests
                && (idle_expired || self.config.pool.max_idle_connections == 0)))
            && let Ok(mut slot) = self.http2.lock()
        {
            slot.take();
        }
    }

    pub(crate) fn wrap_upload(
        &self,
        inner: Incoming,
        exchange: Arc<ExchangeLease>,
        force_chunked: bool,
        declared_trailers: Option<HashSet<HeaderName>>,
    ) -> RequestBody {
        body::boxed(UploadBody {
            inner: Box::pin(inner),
            exchange: Arc::clone(&exchange),
            timer: Box::pin(tokio::time::sleep(self.config.pool.body_idle_timeout)),
            idle_timeout: self.config.pool.body_idle_timeout,
            force_chunked,
            declared_trailers,
            cancelled: Box::pin(exchange.cancellation.clone().cancelled_owned()),
        })
    }
    pub(crate) fn wrap_response(
        self: &Arc<Self>,
        inner: Incoming,
        exchange: Arc<ExchangeLease>,
        http1: Option<Http1Connection>,
        http2_control: Option<Arc<ConnectionControl>>,
        declared_trailers: Option<HashSet<HeaderName>>,
        force_chunked: bool,
    ) -> ResponseBody {
        body::boxed(PooledResponseBody {
            inner: Box::pin(inner),
            pool: Arc::clone(self),
            exchange,
            http1,
            _http2_control: http2_control,
            timer: Box::pin(tokio::time::sleep(self.config.pool.body_idle_timeout)),
            healthy: true,
            declared_trailers,
            force_chunked,
        })
    }
}

struct UploadBody {
    inner: Pin<Box<Incoming>>,
    exchange: Arc<ExchangeLease>,
    timer: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    force_chunked: bool,
    declared_trailers: Option<HashSet<HeaderName>>,
    cancelled: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}
impl Body for UploadBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "HTTP upload cancelled",
            )
            .into())));
        }
        match self.inner.as_mut().poll_frame(cx) {
            Poll::Ready(frame) => {
                let frame = frame.map(|result| {
                    result.map_err(Into::into).and_then(|frame| {
                        super::headers::sanitize_stream_frame(
                            frame,
                            self.declared_trailers.as_ref(),
                        )
                    })
                });
                if frame.is_none()
                    || (frame.as_ref().is_some_and(|result| result.is_ok())
                        && self.inner.is_end_stream())
                {
                    self.exchange.upload_complete.store(true, Ordering::Release);
                }
                let deadline = tokio::time::Instant::now() + self.idle_timeout;
                self.timer.as_mut().reset(deadline);
                Poll::Ready(frame)
            }
            Poll::Pending => {
                if self.timer.as_mut().poll(cx).is_ready() {
                    self.exchange.cancel();
                    Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "HTTP upload idle timeout",
                    )
                    .into())))
                } else {
                    Poll::Pending
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        if self.force_chunked {
            SizeHint::default()
        } else {
            self.inner.size_hint()
        }
    }
}

struct PooledResponseBody {
    inner: Pin<Box<Incoming>>,
    pool: Arc<UpstreamPool>,
    exchange: Arc<ExchangeLease>,
    http1: Option<Http1Connection>,
    _http2_control: Option<Arc<ConnectionControl>>,
    timer: Pin<Box<Sleep>>,
    healthy: bool,
    declared_trailers: Option<HashSet<HeaderName>>,
    force_chunked: bool,
}
impl PooledResponseBody {
    fn finish_http1(&mut self) {
        if let Some(connection) = self.http1.take()
            && self.healthy
            && self.inner.is_end_stream()
            && self.exchange.upload_complete.load(Ordering::Acquire)
        {
            self.pool.return_http1(connection);
        }
        self.pool.record_activity();
    }
}
impl Drop for PooledResponseBody {
    fn drop(&mut self) {
        self.finish_http1();
        self.exchange.cancel();
    }
}
impl Body for PooledResponseBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.inner.as_mut().poll_frame(cx) {
            Poll::Ready(frame) => {
                let frame = frame.map(|result| {
                    result.map_err(Into::into).and_then(|frame| {
                        super::headers::sanitize_stream_frame(
                            frame,
                            self.declared_trailers.as_ref(),
                        )
                    })
                });
                if frame.as_ref().is_some_and(|result| result.is_err()) {
                    self.healthy = false;
                }
                if frame.is_none() || self.inner.is_end_stream() {
                    self.finish_http1();
                }
                let deadline =
                    tokio::time::Instant::now() + self.pool.config.pool.body_idle_timeout;
                self.timer.as_mut().reset(deadline);
                Poll::Ready(frame)
            }
            Poll::Pending => {
                if self.timer.as_mut().poll(cx).is_ready() {
                    self.healthy = false;
                    self.http1.take();
                    self.exchange.cancel();
                    Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "HTTP response idle timeout",
                    )
                    .into())))
                } else {
                    Poll::Pending
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        if self.force_chunked {
            SizeHint::default()
        } else {
            self.inner.size_hint()
        }
    }
}
