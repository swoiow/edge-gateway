use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http2::{Builder as Http2ClientBuilder, SendRequest};
use hyper::header::{
    CONNECTION, CONTENT_TYPE, HOST, HeaderMap, HeaderValue, TE, TRANSFER_ENCODING, UPGRADE,
};
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use super::{GrpcBackendEndpoint, GrpcRoute, GrpcRouteTable};
use crate::gateway::body::{self, ResponseBody};
use crate::observability::RuntimeObservability;

#[derive(Clone)]
pub(crate) struct GrpcRuntime {
    routes: Arc<GrpcRouteTable>,
    upstreams: Arc<HashMap<SocketAddr, Arc<GrpcUpstream>>>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    observability: RuntimeObservability,
}

impl GrpcRuntime {
    pub(crate) fn new(
        routes: Arc<GrpcRouteTable>,
        connect_timeout: Duration,
        max_concurrent_streams_per_backend: usize,
        shutdown: CancellationToken,
        observability: RuntimeObservability,
    ) -> Self {
        let tasks = TaskTracker::new();
        let executor = TrackedExecutor(tasks.clone());
        let mut upstreams = HashMap::new();

        for route in routes.enabled_routes() {
            upstreams.entry(route.backend().address()).or_insert_with(|| {
                Arc::new(GrpcUpstream::new(
                    route.backend().clone(),
                    connect_timeout,
                    max_concurrent_streams_per_backend,
                    shutdown.child_token(),
                    tasks.clone(),
                    executor.clone(),
                ))
            });
        }

        Self {
            routes,
            upstreams: Arc::new(upstreams),
            shutdown,
            tasks,
            observability,
        }
    }

    pub(crate) fn resolve(&self, path: &str) -> Option<Arc<GrpcRoute>> {
        self.routes.resolve(path)
    }

    pub(crate) fn configured_route_count(&self) -> usize {
        self.routes.configured_count()
    }

    pub(crate) fn enabled_route_count(&self) -> usize {
        self.routes.enabled_count()
    }

    pub(crate) async fn proxy(
        &self,
        request: Request<Incoming>,
        route: Arc<GrpcRoute>,
        peer: SocketAddr,
        transport_connection_id: u64,
    ) -> Response<ResponseBody> {
        let cf_ray = request
            .headers()
            .get("cf-ray")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if self.observability.connection_event_logs_enabled() {
            info!(
                transport_connection_id,
                route_id = route.id(),
                backend = route.backend().display(),
                %peer,
                cf_ray = cf_ray.as_deref().unwrap_or("-"),
                http_version = ?request.version(),
                method = %request.method(),
                "Cloudflare-facing gRPC request received"
            );
        } else {
            debug!(
                transport_connection_id,
                route_id = route.id(),
                backend = route.backend().display(),
                %peer,
                cf_ray = cf_ray.as_deref().unwrap_or("-"),
                http_version = ?request.version(),
                method = %request.method(),
                "Cloudflare-facing gRPC request received"
            );
        }

        if self.shutdown.is_cancelled() {
            return grpc_failure_response("14", "gateway%20shutting%20down");
        }
        if request.version() != Version::HTTP_2 {
            return text_response(StatusCode::HTTP_VERSION_NOT_SUPPORTED, "HTTP/2 required\n");
        }
        if request.method() != Method::POST {
            return text_response(StatusCode::METHOD_NOT_ALLOWED, "POST required\n");
        }
        if request.uri().query().is_some() {
            return text_response(StatusCode::BAD_REQUEST, "query string is not allowed\n");
        }
        if !is_grpc_content_type(request.headers()) {
            return text_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "application/grpc content-type required\n",
            );
        }

        let Some(upstream) = self.upstreams.get(&route.backend().address()) else {
            warn!(
                route_id = route.id(),
                backend = route.backend().display(),
                %peer,
                "gRPC route has no upstream runtime"
            );
            return grpc_failure_response("14", "upstream%20unavailable");
        };

        let permit = match Arc::clone(&upstream.active_streams).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(
                    route_id = route.id(),
                    backend = route.backend().display(),
                    %peer,
                    "gRPC per-backend concurrency limit reached"
                );
                return grpc_failure_response("8", "upstream%20concurrency%20limit%20reached");
            }
        };
        let lease = Arc::new(StreamLease::new(permit));

        let (mut parts, request_body) = request.into_parts();
        parts.uri = route.upstream_uri().clone();
        parts.version = Version::HTTP_2;
        parts.extensions.clear();
        sanitize_request_headers(&mut parts.headers, route.backend());
        let request_body = GrpcRequestBody::new(request_body, Arc::clone(&lease));
        let request = Request::from_parts(parts, request_body);

        match upstream.send(request).await {
            Ok(response) => {
                let (mut parts, response_body) = response.into_parts();
                sanitize_response_headers(&mut parts.headers);
                parts.version = Version::HTTP_2;
                let response_body = GrpcResponseBody::new(
                    response_body,
                    lease,
                    route.id().to_owned(),
                    route.backend().display().to_owned(),
                    peer,
                    cf_ray,
                );
                Response::from_parts(parts, body::boxed(response_body))
            }
            Err(error) => {
                warn!(
                    route_id = route.id(),
                    backend = route.backend().display(),
                    %peer,
                    error = %error,
                    "gRPC upstream request failed"
                );
                grpc_failure_response("14", "upstream%20unavailable")
            }
        }
    }

    pub(crate) fn close(&self) {
        self.shutdown.cancel();
        self.tasks.close();
    }

    pub(crate) async fn wait(&self) {
        self.tasks.wait().await;
    }
}

struct GrpcUpstream {
    endpoint: GrpcBackendEndpoint,
    connect_timeout: Duration,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    executor: TrackedExecutor,
    sender: Mutex<Option<SendRequest<GrpcRequestBody>>>,
    connect_gate: Semaphore,
    active_streams: Arc<Semaphore>,
}

impl GrpcUpstream {
    fn new(
        endpoint: GrpcBackendEndpoint,
        connect_timeout: Duration,
        max_concurrent_streams: usize,
        shutdown: CancellationToken,
        tasks: TaskTracker,
        executor: TrackedExecutor,
    ) -> Self {
        Self {
            endpoint,
            connect_timeout,
            shutdown,
            tasks,
            executor,
            sender: Mutex::new(None),
            connect_gate: Semaphore::new(1),
            active_streams: Arc::new(Semaphore::new(max_concurrent_streams)),
        }
    }

    async fn send(
        &self,
        request: Request<GrpcRequestBody>,
    ) -> Result<Response<Incoming>, GrpcProxyError> {
        let mut sender = self.sender().await?;
        tokio::select! {
            () = self.shutdown.cancelled() => return Err(GrpcProxyError::ShuttingDown),
            result = sender.ready() => {
                result.map_err(GrpcProxyError::Upstream)?;
            }
        }

        tokio::select! {
            () = self.shutdown.cancelled() => Err(GrpcProxyError::ShuttingDown),
            result = sender.send_request(request) => result.map_err(GrpcProxyError::Upstream),
        }
    }

    async fn sender(&self) -> Result<SendRequest<GrpcRequestBody>, GrpcProxyError> {
        if let Some(sender) = self.cached_sender().await {
            return Ok(sender);
        }

        let _connect_permit = tokio::select! {
            () = self.shutdown.cancelled() => return Err(GrpcProxyError::ShuttingDown),
            result = self.connect_gate.acquire() => {
                result.map_err(|_| GrpcProxyError::ShuttingDown)?
            }
        };

        if let Some(sender) = self.cached_sender().await {
            return Ok(sender);
        }

        let endpoint = self.endpoint.clone();
        let executor = self.executor.clone();
        let connection = async move {
            let stream =
                TcpStream::connect(endpoint.address()).await.map_err(GrpcProxyError::Connect)?;
            configure_tcp_stream(&stream)?;
            let io = TokioIo::new(stream);
            Http2ClientBuilder::new(executor)
                .handshake::<_, GrpcRequestBody>(io)
                .await
                .map_err(GrpcProxyError::Handshake)
        };

        let (sender, driver) = tokio::select! {
            () = self.shutdown.cancelled() => return Err(GrpcProxyError::ShuttingDown),
            result = timeout(self.connect_timeout, connection) => {
                result.map_err(|_| GrpcProxyError::ConnectTimeout)??
            }
        };

        let shutdown = self.shutdown.child_token();
        let backend = self.endpoint.display().to_owned();
        let driver_task = self.tasks.spawn(async move {
            tokio::select! {
                result = driver => {
                    match result {
                        Ok(()) => debug!(%backend, "gRPC upstream HTTP/2 connection closed"),
                        Err(error) => {
                            warn!(
                                %backend,
                                error = %error,
                                "gRPC upstream HTTP/2 connection failed"
                            );
                        }
                    }
                }
                () = shutdown.cancelled() => {
                    debug!(%backend, "gRPC upstream HTTP/2 connection cancelled");
                }
            }
        });
        std::mem::drop(driver_task);

        {
            let mut cached = self.sender.lock().await;
            *cached = Some(sender.clone());
        }

        debug!(
            backend = self.endpoint.display(),
            "gRPC upstream HTTP/2 connection established"
        );
        Ok(sender)
    }

    async fn cached_sender(&self) -> Option<SendRequest<GrpcRequestBody>> {
        let cached = self.sender.lock().await;
        cached.as_ref().filter(|sender| !sender.is_closed()).cloned()
    }
}

fn configure_tcp_stream(stream: &TcpStream) -> Result<(), GrpcProxyError> {
    stream.set_nodelay(true).map_err(GrpcProxyError::ConfigureSocket)
}

fn is_grpc_content_type(headers: &HeaderMap) -> bool {
    const GRPC_PREFIX: &str = "application/grpc+";

    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value.split(';').next().map(str::trim).unwrap_or_default();
            media_type.eq_ignore_ascii_case("application/grpc")
                || (media_type.len() > GRPC_PREFIX.len()
                    && media_type
                        .get(..GRPC_PREFIX.len())
                        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(GRPC_PREFIX)))
        })
}

fn sanitize_request_headers(headers: &mut HeaderMap, endpoint: &GrpcBackendEndpoint) {
    remove_connection_specific_headers(headers);
    headers.insert(HOST, endpoint.host_header().clone());
    headers.insert(TE, HeaderValue::from_static("trailers"));
}

fn sanitize_response_headers(headers: &mut HeaderMap) {
    remove_connection_specific_headers(headers);
}

fn remove_connection_specific_headers(headers: &mut HeaderMap) {
    headers.remove(CONNECTION);
    headers.remove(TE);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

fn text_response(status: StatusCode, message: &'static str) -> Response<ResponseBody> {
    let mut response = Response::new(body::boxed(Full::new(Bytes::from_static(
        message.as_bytes(),
    ))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn grpc_failure_response(status: &'static str, message: &'static str) -> Response<ResponseBody> {
    let mut response = Response::new(body::boxed(Empty::<Bytes>::new()));
    *response.status_mut() = StatusCode::OK;
    *response.version_mut() = Version::HTTP_2;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    response.headers_mut().insert("grpc-status", HeaderValue::from_static(status));
    response.headers_mut().insert("grpc-message", HeaderValue::from_static(message));
    response
}

struct StreamLease {
    _permit: OwnedSemaphorePermit,
}

impl StreamLease {
    fn new(permit: OwnedSemaphorePermit) -> Self {
        Self { _permit: permit }
    }
}

struct GrpcRequestBody {
    inner: Pin<Box<Incoming>>,
    lease: Option<Arc<StreamLease>>,
}

impl GrpcRequestBody {
    fn new(inner: Incoming, lease: Arc<StreamLease>) -> Self {
        Self {
            inner: Box::pin(inner),
            lease: Some(lease),
        }
    }
}

impl Body for GrpcRequestBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let frame = self.inner.as_mut().poll_frame(context);
        if matches!(&frame, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.lease.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct GrpcResponseBody {
    inner: Pin<Box<Incoming>>,
    lease: Option<Arc<StreamLease>>,
    route_id: String,
    backend: String,
    peer: SocketAddr,
    cf_ray: Option<String>,
    started_at: Instant,
    finished: bool,
}

impl GrpcResponseBody {
    fn new(
        inner: Incoming,
        lease: Arc<StreamLease>,
        route_id: String,
        backend: String,
        peer: SocketAddr,
        cf_ray: Option<String>,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            lease: Some(lease),
            route_id,
            backend,
            peer,
            cf_ray,
            started_at: Instant::now(),
            finished: false,
        }
    }

    fn finish(&mut self, reason: &'static str) {
        if self.finished {
            return;
        }

        self.finished = true;
        self.lease.take();
        debug!(
            route_id = %self.route_id,
            backend = %self.backend,
            peer = %self.peer,
            cf_ray = self.cf_ray.as_deref().unwrap_or(""),
            duration_ms = self.started_at.elapsed().as_millis(),
            %reason,
            "gRPC response stream finished"
        );
    }
}

impl Body for GrpcResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.inner.as_mut().poll_frame(context) {
            Poll::Ready(None) => {
                self.finish("complete");
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish("upstream_error");
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for GrpcResponseBody {
    fn drop(&mut self) {
        if !self.finished {
            self.finish("downstream_cancelled");
        }
    }
}

#[derive(Debug, Error)]
enum GrpcProxyError {
    #[error("gateway is shutting down")]
    ShuttingDown,
    #[error("gRPC upstream connection timed out")]
    ConnectTimeout,
    #[error("failed to connect to gRPC upstream: {0}")]
    Connect(#[source] std::io::Error),
    #[error("failed to configure gRPC upstream socket: {0}")]
    ConfigureSocket(#[source] std::io::Error),
    #[error("gRPC upstream HTTP/2 handshake failed: {0}")]
    Handshake(#[source] hyper::Error),
    #[error("gRPC upstream HTTP/2 request failed: {0}")]
    Upstream(#[source] hyper::Error),
}

#[derive(Clone)]
struct TrackedExecutor(TaskTracker);

impl<Fut> hyper::rt::Executor<Fut> for TrackedExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, future: Fut) {
        let task = self.0.spawn(future);
        std::mem::drop(task);
    }
}
