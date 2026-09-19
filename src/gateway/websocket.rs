use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use fastwebsockets::{WebSocket, WebSocketError, handshake, upgrade};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HOST, UPGRADE};
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use crate::config::ServerConfig;
use crate::gateway::relay;
use crate::gateway::relay::ConnectionContext;
use crate::observability::RuntimeObservability;
use crate::routes::Route;

type GatewayWebSocket = WebSocket<TokioIo<Upgraded>>;

#[derive(Clone)]
pub(super) struct WebSocketRuntime {
    server_config: Arc<ServerConfig>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    executor: TrackedExecutor,
    observability: RuntimeObservability,
}

impl WebSocketRuntime {
    pub(super) fn new(
        server_config: Arc<ServerConfig>,
        shutdown: CancellationToken,
        observability: RuntimeObservability,
    ) -> Self {
        let tasks = TaskTracker::new();
        Self {
            server_config,
            shutdown,
            executor: TrackedExecutor(tasks.clone()),
            tasks,
            observability,
        }
    }

    pub(super) async fn accept(
        &self,
        mut request: Request<Incoming>,
        route: Arc<Route>,
        peer: SocketAddr,
        transport_connection_id: u64,
    ) -> Result<Response<Empty<Bytes>>, AcceptError> {
        if self.shutdown.is_cancelled() {
            return Err(AcceptError::ShuttingDown);
        }
        if request.method() != Method::GET || !upgrade::is_upgrade_request(&request) {
            return Err(AcceptError::UpgradeRequired);
        }

        let connection_id = self.observability.next_websocket_connection_id();
        let downstream_http_version = http_version(request.version());
        let cf_ray = request
            .headers()
            .get("cf-ray")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let (response, downstream_upgrade) =
            upgrade::upgrade(&mut request).map_err(AcceptError::InvalidHandshake)?;

        let backend_connect_started = Instant::now();
        let backend = tokio::select! {
            () = self.shutdown.cancelled() => return Err(AcceptError::ShuttingDown),
            result = timeout(
                self.server_config.backend_connect_timeout(),
                connect_backend(&route, &self.executor),
            ) => {
                match result {
                    Ok(Ok(backend)) => backend,
                    Ok(Err(error)) => {
                        self.observability.record_websocket_backend_connect_failure();
                        warn!(
                            transport_connection_id,
                            connection_id,
                            route_id = route.id(),
                            route_class = route.namespace().as_str(),
                            backend = route.backend().display(),
                            %peer,
                            cf_ray = cf_ray.as_deref().unwrap_or("-"),
                            connect_duration_ms = backend_connect_started.elapsed().as_millis(),
                            error = %error,
                            "V2Fly WebSocket backend connection failed"
                        );
                        return Err(AcceptError::Backend(error));
                    }
                    Err(_) => {
                        self.observability.record_websocket_backend_connect_timeout();
                        warn!(
                            transport_connection_id,
                            connection_id,
                            route_id = route.id(),
                            route_class = route.namespace().as_str(),
                            backend = route.backend().display(),
                            %peer,
                            cf_ray = cf_ray.as_deref().unwrap_or("-"),
                            connect_duration_ms = backend_connect_started.elapsed().as_millis(),
                            timeout_seconds = self.server_config.backend_connect_timeout().as_secs(),
                            "V2Fly WebSocket backend connection timed out"
                        );
                        return Err(AcceptError::BackendTimeout);
                    }
                }
            }
        };

        let shutdown = self.shutdown.child_token();
        let upgrade_timeout = self.server_config.websocket_upgrade_timeout();
        let max_message_size = self.server_config.max_websocket_message_size();
        let route_for_relay = Arc::clone(&route);
        let observability = self.observability.clone();
        let backend_connect_duration_ms = backend_connect_started.elapsed().as_millis();

        debug!(
            transport_connection_id,
            connection_id,
            route_id = route.id(),
            route_class = route.namespace().as_str(),
            backend = route.backend().display(),
            %peer,
            cf_ray = cf_ray.as_deref().unwrap_or("-"),
            backend_connect_duration_ms,
            "V2Fly WebSocket backend connected"
        );

        let relay_task = self.tasks.spawn(async move {
            let upgrade_started = Instant::now();
            let downstream = match timeout(upgrade_timeout, downstream_upgrade).await {
                Ok(Ok(downstream)) => downstream,
                Ok(Err(error)) => {
                    observability.record_websocket_upgrade_failure();
                    warn!(
                        transport_connection_id,
                        connection_id,
                        route_id = route_for_relay.id(),
                        route_class = route_for_relay.namespace().as_str(),
                        %peer,
                        cf_ray = cf_ray.as_deref().unwrap_or("-"),
                        upgrade_duration_ms = upgrade_started.elapsed().as_millis(),
                        error = %error,
                        "downstream WebSocket upgrade failed"
                    );
                    return;
                }
                Err(_) => {
                    observability.record_websocket_upgrade_timeout();
                    warn!(
                        transport_connection_id,
                        connection_id,
                        route_id = route_for_relay.id(),
                        route_class = route_for_relay.namespace().as_str(),
                        %peer,
                        cf_ray = cf_ray.as_deref().unwrap_or("-"),
                        timeout_seconds = upgrade_timeout.as_secs(),
                        upgrade_duration_ms = upgrade_started.elapsed().as_millis(),
                        "downstream WebSocket upgrade timed out"
                    );
                    return;
                }
            };

            let active_connection = observability.begin_websocket_connection();
            if observability.connection_event_logs_enabled() {
                info!(
                    transport_connection_id,
                    connection_id,
                    route_id = route_for_relay.id(),
                    route_class = route_for_relay.namespace().as_str(),
                    backend = route_for_relay.backend().display(),
                    %peer,
                    cf_ray = cf_ray.as_deref().unwrap_or("-"),
                    downstream_http_version,
                    backend_connect_duration_ms,
                    upgrade_duration_ms = upgrade_started.elapsed().as_millis(),
                    active_websocket_connections = active_connection.active_connections(),
                    peak_websocket_connections = observability.peak_websocket_connections(),
                    "Cloudflare-facing WebSocket connection established"
                );
            }

            relay::run(
                ConnectionContext {
                    transport_connection_id,
                    connection_id,
                    peer,
                    route: route_for_relay,
                    cf_ray,
                    downstream_http_version,
                    active_connection,
                    observability,
                },
                downstream,
                backend,
                shutdown,
                max_message_size,
            )
            .await;
        });
        std::mem::drop(relay_task);

        Ok(response)
    }

    pub(super) fn close(&self) {
        self.tasks.close();
    }

    pub(super) async fn wait(&self) {
        self.tasks.wait().await;
    }
}

async fn connect_backend(route: &Route, executor: &TrackedExecutor) -> Result<GatewayWebSocket> {
    let stream = TcpStream::connect(route.backend().address()).await.with_context(|| {
        format!(
            "failed to connect to V2Fly backend {}",
            route.backend().display()
        )
    })?;
    stream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY for V2Fly backend")?;

    let request = Request::builder()
        .method(Method::GET)
        .uri(route.backend().request_target().clone())
        .header(HOST, route.backend().host_header().clone())
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header("Sec-WebSocket-Key", handshake::generate_key())
        .header("Sec-WebSocket-Version", "13")
        .body(Empty::<Bytes>::new())
        .context("failed to build V2Fly WebSocket handshake request")?;

    let (websocket, _response) = handshake::client(executor, request, stream)
        .await
        .context("V2Fly WebSocket handshake failed")?;
    Ok(websocket)
}

fn http_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "unknown",
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum AcceptError {
    #[error("request is not a supported WebSocket upgrade")]
    UpgradeRequired,
    #[error("invalid WebSocket handshake: {0}")]
    InvalidHandshake(#[source] WebSocketError),
    #[error("gateway is shutting down")]
    ShuttingDown,
    #[error("V2Fly backend connection timed out")]
    BackendTimeout,
    #[error("V2Fly backend connection failed: {0}")]
    Backend(#[source] anyhow::Error),
}

impl AcceptError {
    pub(super) const fn status(&self) -> StatusCode {
        match self {
            Self::UpgradeRequired => StatusCode::UPGRADE_REQUIRED,
            Self::InvalidHandshake(_) => StatusCode::BAD_REQUEST,
            Self::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendTimeout | Self::Backend(_) => StatusCode::BAD_GATEWAY,
        }
    }

    pub(super) const fn public_message(&self) -> &'static str {
        match self {
            Self::UpgradeRequired => "websocket upgrade required\n",
            Self::InvalidHandshake(_) => "invalid websocket handshake\n",
            Self::ShuttingDown => "gateway is shutting down\n",
            Self::BackendTimeout | Self::Backend(_) => "backend unavailable\n",
        }
    }

    pub(super) const fn is_backend_failure(&self) -> bool {
        matches!(self, Self::BackendTimeout | Self::Backend(_))
    }
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
