use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use fastwebsockets::{Role, WebSocket, WebSocketError, handshake, upgrade};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::ext::Protocol;
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
use crate::gateway::body::{self, ResponseBody};
use crate::gateway::h2_websocket::split_extended_connect_body;
use crate::gateway::relay::{self, ConnectionContext, RelaySocket};
use crate::observability::RuntimeObservability;
use crate::routes::{Route, RouteNamespace};

type GatewayWebSocket = WebSocket<TokioIo<Upgraded>>;

const HEADER_INGRESS_TRANSPORT_ID: &str = "x-edge-gateway-ingress-transport-id";
const HEADER_WEBSOCKET_ID: &str = "x-edge-gateway-websocket-id";
const HEADER_INGRESS_PEER: &str = "x-edge-gateway-ingress-peer";
const HEADER_DOWNSTREAM_HTTP_VERSION: &str = "x-edge-gateway-downstream-http-version";
const HEADER_DOWNSTREAM_HANDSHAKE: &str = "x-edge-gateway-downstream-handshake";
const HEADER_CF_RAY: &str = "x-edge-gateway-cf-ray";

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
    ) -> Result<Response<ResponseBody>, AcceptError> {
        if self.shutdown.is_cancelled() {
            return Err(AcceptError::ShuttingDown);
        }

        let handshake_kind = validate_downstream_handshake(&request)?;
        let connection_id = self.observability.next_websocket_connection_id();
        let downstream_http_version = http_version(request.version());
        let cf_ray = request
            .headers()
            .get("cf-ray")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let backend_metadata = BackendHandshakeMetadata {
            transport_connection_id,
            connection_id,
            peer,
            cf_ray: cf_ray.clone(),
            downstream_http_version,
            downstream_handshake: handshake_kind.as_str(),
        };

        let h1_upgrade = if handshake_kind == DownstreamHandshake::Http1Upgrade {
            let (response, downstream_upgrade) =
                upgrade::upgrade(&mut request).map_err(AcceptError::InvalidHandshake)?;
            Some((response, downstream_upgrade))
        } else {
            None
        };

        let backend_connect_started = Instant::now();
        let backend = tokio::select! {
            () = self.shutdown.cancelled() => return Err(AcceptError::ShuttingDown),
            result = timeout(
                self.server_config.backend_connect_timeout(),
                connect_backend(&route, &self.executor, &backend_metadata),
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
                            downstream_http_version,
                            downstream_handshake = handshake_kind.as_str(),
                            connect_duration_ms = backend_connect_started.elapsed().as_millis(),
                            error = %error,
                            "WebSocket backend connection failed"
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
                            downstream_http_version,
                            downstream_handshake = handshake_kind.as_str(),
                            connect_duration_ms = backend_connect_started.elapsed().as_millis(),
                            timeout_seconds = self.server_config.backend_connect_timeout().as_secs(),
                            "WebSocket backend connection timed out"
                        );
                        return Err(AcceptError::BackendTimeout);
                    }
                }
            }
        };

        let backend_connect_duration_ms = backend_connect_started.elapsed().as_millis();
        debug!(
            transport_connection_id,
            connection_id,
            route_id = route.id(),
            route_class = route.namespace().as_str(),
            backend = route.backend().display(),
            %peer,
            cf_ray = cf_ray.as_deref().unwrap_or("-"),
            downstream_http_version,
            downstream_handshake = handshake_kind.as_str(),
            backend_connect_duration_ms,
            "WebSocket backend connected"
        );

        match handshake_kind {
            DownstreamHandshake::Http1Upgrade => {
                let Some((response, downstream_upgrade)) = h1_upgrade else {
                    return Err(AcceptError::InvalidInternalState);
                };
                self.spawn_http1_relay(
                    downstream_upgrade,
                    backend,
                    RelayLaunchContext {
                        transport_connection_id,
                        connection_id,
                        peer,
                        route,
                        cf_ray,
                        downstream_http_version,
                        downstream_handshake: handshake_kind.as_str(),
                        backend_connect_duration_ms,
                    },
                );
                Ok(response.map(body::boxed))
            }
            DownstreamHandshake::Http2ExtendedConnect => {
                let request_body = request.into_body();
                let (downstream_read, downstream_write, response_body) =
                    split_extended_connect_body(request_body);
                let downstream =
                    RelaySocket::from_io_halves(downstream_read, downstream_write, Role::Server);
                let backend = RelaySocket::from_upgraded_websocket(backend, Role::Client);
                self.spawn_established_relay(
                    downstream,
                    backend,
                    RelayLaunchContext {
                        transport_connection_id,
                        connection_id,
                        peer,
                        route,
                        cf_ray,
                        downstream_http_version,
                        downstream_handshake: handshake_kind.as_str(),
                        backend_connect_duration_ms,
                    },
                    0,
                );

                let mut response = Response::new(body::boxed(response_body));
                *response.status_mut() = StatusCode::OK;
                Ok(response)
            }
        }
    }

    fn spawn_http1_relay(
        &self,
        downstream_upgrade: upgrade::UpgradeFut,
        backend: GatewayWebSocket,
        context: RelayLaunchContext,
    ) {
        let shutdown = self.shutdown.child_token();
        let upgrade_timeout = self.server_config.websocket_upgrade_timeout();
        let max_message_size = self.server_config.max_websocket_message_size();
        let observability = self.observability.clone();
        let tasks = self.tasks.clone();

        let relay_task = tasks.spawn(async move {
            let upgrade_started = Instant::now();
            let downstream = match timeout(upgrade_timeout, downstream_upgrade).await {
                Ok(Ok(downstream)) => downstream,
                Ok(Err(error)) => {
                    observability.record_websocket_upgrade_failure();
                    warn!(
                        transport_connection_id = context.transport_connection_id,
                        connection_id = context.connection_id,
                        route_id = context.route.id(),
                        route_class = context.route.namespace().as_str(),
                        peer = %context.peer,
                        cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
                        downstream_handshake = context.downstream_handshake,
                        upgrade_duration_ms = upgrade_started.elapsed().as_millis(),
                        error = %error,
                        "downstream WebSocket upgrade failed"
                    );
                    return;
                }
                Err(_) => {
                    observability.record_websocket_upgrade_timeout();
                    warn!(
                        transport_connection_id = context.transport_connection_id,
                        connection_id = context.connection_id,
                        route_id = context.route.id(),
                        route_class = context.route.namespace().as_str(),
                        peer = %context.peer,
                        cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
                        downstream_handshake = context.downstream_handshake,
                        timeout_seconds = upgrade_timeout.as_secs(),
                        upgrade_duration_ms = upgrade_started.elapsed().as_millis(),
                        "downstream WebSocket upgrade timed out"
                    );
                    return;
                }
            };

            let downstream = RelaySocket::from_upgraded_websocket(downstream, Role::Server);
            let backend = RelaySocket::from_upgraded_websocket(backend, Role::Client);
            start_relay(
                downstream,
                backend,
                context,
                observability,
                shutdown,
                max_message_size,
                upgrade_started.elapsed().as_millis(),
            )
            .await;
        });
        std::mem::drop(relay_task);
    }

    fn spawn_established_relay(
        &self,
        downstream: RelaySocket,
        backend: RelaySocket,
        context: RelayLaunchContext,
        handshake_duration_ms: u128,
    ) {
        let shutdown = self.shutdown.child_token();
        let max_message_size = self.server_config.max_websocket_message_size();
        let observability = self.observability.clone();
        let tasks = self.tasks.clone();
        let relay_task = tasks.spawn(async move {
            start_relay(
                downstream,
                backend,
                context,
                observability,
                shutdown,
                max_message_size,
                handshake_duration_ms,
            )
            .await;
        });
        std::mem::drop(relay_task);
    }

    pub(super) fn close(&self) {
        self.tasks.close();
    }

    pub(super) async fn wait(&self) {
        self.tasks.wait().await;
    }
}

async fn start_relay(
    downstream: RelaySocket,
    backend: RelaySocket,
    context: RelayLaunchContext,
    observability: RuntimeObservability,
    shutdown: CancellationToken,
    max_message_size: usize,
    handshake_duration_ms: u128,
) {
    let active_connection = observability.begin_websocket_connection();
    if observability.connection_event_logs_enabled() {
        info!(
            transport_connection_id = context.transport_connection_id,
            connection_id = context.connection_id,
            route_id = context.route.id(),
            route_class = context.route.namespace().as_str(),
            backend = context.route.backend().display(),
            peer = %context.peer,
            cf_ray = context.cf_ray.as_deref().unwrap_or("-"),
            downstream_http_version = context.downstream_http_version,
            downstream_handshake = context.downstream_handshake,
            backend_connect_duration_ms = context.backend_connect_duration_ms,
            handshake_duration_ms,
            active_websocket_connections = active_connection.active_connections(),
            peak_websocket_connections = observability.peak_websocket_connections(),
            "Cloudflare-facing WebSocket connection established"
        );
    }

    relay::run(
        ConnectionContext {
            transport_connection_id: context.transport_connection_id,
            connection_id: context.connection_id,
            peer: context.peer,
            route: context.route,
            cf_ray: context.cf_ray,
            downstream_http_version: context.downstream_http_version,
            active_connection,
            observability,
        },
        downstream,
        backend,
        shutdown,
        max_message_size,
    )
    .await;
}

async fn connect_backend(
    route: &Route,
    executor: &TrackedExecutor,
    metadata: &BackendHandshakeMetadata,
) -> Result<GatewayWebSocket> {
    let stream = TcpStream::connect(route.backend().address()).await.with_context(|| {
        format!(
            "failed to connect to WebSocket backend {}",
            route.backend().display()
        )
    })?;
    stream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY for WebSocket backend")?;

    let mut request = Request::builder()
        .method(Method::GET)
        .uri(route.backend().request_target().clone())
        .header(HOST, route.backend().host_header().clone())
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header("Sec-WebSocket-Key", handshake::generate_key())
        .header("Sec-WebSocket-Version", "13");

    if route.namespace() == RouteNamespace::Uat {
        request = request
            .header(
                HEADER_INGRESS_TRANSPORT_ID,
                metadata.transport_connection_id.to_string(),
            )
            .header(HEADER_WEBSOCKET_ID, metadata.connection_id.to_string())
            .header(HEADER_INGRESS_PEER, metadata.peer.to_string())
            .header(
                HEADER_DOWNSTREAM_HTTP_VERSION,
                metadata.downstream_http_version,
            )
            .header(HEADER_DOWNSTREAM_HANDSHAKE, metadata.downstream_handshake);
        if let Some(cf_ray) = &metadata.cf_ray {
            request = request.header(HEADER_CF_RAY, cf_ray);
        }
    }

    let request = request
        .body(Empty::<Bytes>::new())
        .context("failed to build WebSocket backend handshake request")?;

    let (websocket, _response) = handshake::client(executor, request, stream)
        .await
        .context("WebSocket backend handshake failed")?;
    Ok(websocket)
}

fn validate_downstream_handshake(
    request: &Request<Incoming>,
) -> Result<DownstreamHandshake, AcceptError> {
    match request.version() {
        Version::HTTP_11 => {
            if request.method() == Method::GET && upgrade::is_upgrade_request(request) {
                Ok(DownstreamHandshake::Http1Upgrade)
            } else {
                Err(AcceptError::Http1UpgradeRequired)
            }
        }
        Version::HTTP_2 => {
            let is_websocket_connect = request.method() == Method::CONNECT
                && request
                    .extensions()
                    .get::<Protocol>()
                    .is_some_and(|protocol| protocol.as_str().eq_ignore_ascii_case("websocket"));
            let is_version_13 = request
                .headers()
                .get("sec-websocket-version")
                .and_then(|value| value.to_str().ok())
                == Some("13");

            if is_websocket_connect && is_version_13 {
                Ok(DownstreamHandshake::Http2ExtendedConnect)
            } else {
                Err(AcceptError::Http2ExtendedConnectRequired)
            }
        }
        _ => Err(AcceptError::UnsupportedHttpVersion),
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DownstreamHandshake {
    Http1Upgrade,
    Http2ExtendedConnect,
}

impl DownstreamHandshake {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Http1Upgrade => "http1_upgrade",
            Self::Http2ExtendedConnect => "rfc8441_extended_connect",
        }
    }
}

struct BackendHandshakeMetadata {
    transport_connection_id: u64,
    connection_id: u64,
    peer: SocketAddr,
    cf_ray: Option<String>,
    downstream_http_version: &'static str,
    downstream_handshake: &'static str,
}

struct RelayLaunchContext {
    transport_connection_id: u64,
    connection_id: u64,
    peer: SocketAddr,
    route: Arc<Route>,
    cf_ray: Option<String>,
    downstream_http_version: &'static str,
    downstream_handshake: &'static str,
    backend_connect_duration_ms: u128,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum AcceptError {
    #[error("HTTP/1.1 request is not a supported WebSocket upgrade")]
    Http1UpgradeRequired,
    #[error("HTTP/2 request is not an RFC 8441 WebSocket extended CONNECT")]
    Http2ExtendedConnectRequired,
    #[error("HTTP version does not support this WebSocket endpoint")]
    UnsupportedHttpVersion,
    #[error("invalid WebSocket handshake: {0}")]
    InvalidHandshake(#[source] WebSocketError),
    #[error("gateway entered an invalid WebSocket handshake state")]
    InvalidInternalState,
    #[error("gateway is shutting down")]
    ShuttingDown,
    #[error("WebSocket backend connection timed out")]
    BackendTimeout,
    #[error("WebSocket backend connection failed: {0}")]
    Backend(#[source] anyhow::Error),
}

impl AcceptError {
    pub(super) const fn status(&self) -> StatusCode {
        match self {
            Self::Http1UpgradeRequired => StatusCode::UPGRADE_REQUIRED,
            Self::Http2ExtendedConnectRequired | Self::InvalidHandshake(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::UnsupportedHttpVersion => StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            Self::InvalidInternalState => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
            Self::BackendTimeout | Self::Backend(_) => StatusCode::BAD_GATEWAY,
        }
    }

    pub(super) const fn public_message(&self) -> &'static str {
        match self {
            Self::Http1UpgradeRequired => "HTTP/1.1 websocket upgrade required\n",
            Self::Http2ExtendedConnectRequired => {
                "HTTP/2 RFC 8441 websocket extended CONNECT required\n"
            }
            Self::UnsupportedHttpVersion => "unsupported websocket HTTP version\n",
            Self::InvalidHandshake(_) => "invalid websocket handshake\n",
            Self::InvalidInternalState => "internal websocket state error\n",
            Self::ShuttingDown => "gateway is shutting down\n",
            Self::BackendTimeout | Self::Backend(_) => "backend unavailable\n",
        }
    }

    pub(super) const fn should_advertise_http1_upgrade(&self) -> bool {
        matches!(self, Self::Http1UpgradeRequired)
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
