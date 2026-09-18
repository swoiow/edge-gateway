use std::convert::Infallible;
use std::future::Future;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue, UPGRADE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnectionBuilder;
use rustls::ServerConfig as RustlsServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::{ServerConfig, TlsConfig};
use crate::gateway::body::{self, ResponseBody};
use crate::gateway::websocket::WebSocketRuntime;
use crate::grpc::{GrpcRouteTable, GrpcRuntime};
use crate::routes::RouteTable;

pub(super) async fn run<F>(
    server_config: ServerConfig,
    tls_config: TlsConfig,
    routes: Arc<RouteTable>,
    grpc_routes: Arc<GrpcRouteTable>,
    shutdown_signal: F,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let tls_acceptor = build_tls_acceptor(&tls_config).await?;
    let listener = TcpListener::bind(server_config.listen())
        .await
        .with_context(|| format!("failed to bind listener on {}", server_config.listen()))?;

    let server_config = Arc::new(server_config);
    let cancellation = CancellationToken::new();
    let websocket_runtime =
        WebSocketRuntime::new(Arc::clone(&server_config), cancellation.child_token());
    let grpc_runtime = GrpcRuntime::new(
        grpc_routes,
        server_config.backend_connect_timeout(),
        server_config.max_grpc_concurrent_streams_per_backend(),
        cancellation.child_token(),
    );
    let service_state = ServiceState {
        routes: Arc::clone(&routes),
        websocket: websocket_runtime.clone(),
        grpc: grpc_runtime.clone(),
    };

    info!(
        listen = %server_config.listen(),
        configured_websocket_routes = routes.configured_count(),
        enabled_websocket_routes = routes.enabled_count(),
        configured_grpc_routes = grpc_runtime.configured_route_count(),
        enabled_grpc_routes = grpc_runtime.enabled_route_count(),
        "gateway listener started"
    );

    let mut connections = JoinSet::new();
    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            biased;

            () = &mut shutdown_signal => {
                info!("shutdown signal received; stopping listener");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("failed to accept TCP connection")?;
                let acceptor = tls_acceptor.clone();
                let connection_cancellation = cancellation.child_token();
                let handshake_timeout = server_config.tls_handshake_timeout();
                let shutdown_grace = server_config.shutdown_grace();
                let state = service_state.clone();

                connections.spawn(async move {
                    serve_connection(
                        stream,
                        acceptor,
                        connection_cancellation,
                        handshake_timeout,
                        shutdown_grace,
                        peer,
                        state,
                    )
                    .await;
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "connection task terminated unexpectedly");
                }
            }
        }
    }

    cancellation.cancel();
    websocket_runtime.close();
    grpc_runtime.close();

    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            warn!(error = %error, "connection task terminated unexpectedly during shutdown");
        }
    }

    let data_plane_shutdown = async {
        tokio::join!(websocket_runtime.wait(), grpc_runtime.wait());
    };
    if timeout(server_config.shutdown_grace(), data_plane_shutdown).await.is_err() {
        warn!(
            timeout_seconds = server_config.shutdown_grace().as_secs(),
            "data-plane tasks exceeded shutdown grace period"
        );
    }

    info!("gateway shutdown complete");
    Ok(())
}

#[derive(Clone)]
struct ServiceState {
    routes: Arc<RouteTable>,
    websocket: WebSocketRuntime,
    grpc: GrpcRuntime,
}

async fn build_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let certificate_bytes = tokio::fs::read(config.cert())
        .await
        .with_context(|| format!("failed to read TLS certificate {}", config.cert().display()))?;
    let key_bytes = tokio::fs::read(config.key())
        .await
        .with_context(|| format!("failed to read TLS private key {}", config.key().display()))?;

    let mut certificate_reader = BufReader::new(certificate_bytes.as_slice());
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse TLS certificate chain")?;

    if certificates.is_empty() {
        return Err(anyhow!("TLS certificate file contains no certificates"));
    }

    let mut key_reader = BufReader::new(key_bytes.as_slice());
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to parse TLS private key")?
        .ok_or_else(|| anyhow!("TLS private key file contains no supported private key"))?;

    let mut tls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("TLS certificate and private key are incompatible")?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

async fn serve_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    cancellation: CancellationToken,
    handshake_timeout: Duration,
    shutdown_grace: Duration,
    peer: std::net::SocketAddr,
    state: ServiceState,
) {
    let tls_stream = match timeout(handshake_timeout, acceptor.accept(stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            warn!(%peer, error = %error, "TLS handshake failed");
            return;
        }
        Err(_) => {
            warn!(%peer, timeout_seconds = handshake_timeout.as_secs(), "TLS handshake timed out");
            return;
        }
    };

    let alpn = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
        .unwrap_or_else(|| "none".to_owned());
    debug!(%peer, %alpn, "TLS handshake completed");

    let service = service_fn(move |request| handle_request(request, state.clone(), peer));
    let io = TokioIo::new(tls_stream);
    let builder = AutoConnectionBuilder::new(TokioExecutor::new());
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);

    tokio::select! {
        result = &mut connection => {
            if let Err(error) = result {
                debug!(%peer, error = %error, "HTTP connection closed with an error");
            }
        }
        () = cancellation.cancelled() => {
            connection.as_mut().graceful_shutdown();

            match timeout(shutdown_grace, &mut connection).await {
                Ok(Ok(())) => {
                    debug!(%peer, "HTTP connection closed gracefully");
                }
                Ok(Err(error)) => {
                    debug!(%peer, error = %error, "HTTP connection failed during graceful shutdown");
                }
                Err(_) => {
                    warn!(
                        %peer,
                        timeout_seconds = shutdown_grace.as_secs(),
                        "HTTP connection exceeded shutdown grace period"
                    );
                }
            }
        }
    }
}

async fn handle_request(
    request: Request<Incoming>,
    state: ServiceState,
    peer: std::net::SocketAddr,
) -> std::result::Result<Response<ResponseBody>, Infallible> {
    if request.method() == Method::GET
        && matches!(request.uri().path(), "/health/live" | "/health/ready")
    {
        return Ok(text_response(StatusCode::OK, "ok\n"));
    }

    let path = request.uri().path();
    if let Some(route) = state.routes.resolve(path) {
        return match state.websocket.accept(request, Arc::clone(&route), peer).await {
            Ok(response) => Ok(response.map(body::boxed)),
            Err(error) => {
                if error.is_backend_failure() {
                    warn!(
                        route_id = route.id(),
                        route_class = route.namespace().as_str(),
                        backend = route.backend().display(),
                        %peer,
                        error = %error,
                        "WebSocket request rejected"
                    );
                } else {
                    debug!(
                        route_id = route.id(),
                        route_class = route.namespace().as_str(),
                        %peer,
                        error = %error,
                        "WebSocket request rejected"
                    );
                }

                let mut response = text_response(error.status(), error.public_message());
                if error.status() == StatusCode::UPGRADE_REQUIRED {
                    response.headers_mut().insert(UPGRADE, HeaderValue::from_static("websocket"));
                }
                Ok(response)
            }
        };
    }

    if let Some(route) = state.grpc.resolve(path) {
        return Ok(state.grpc.proxy(request, route, peer).await);
    }

    Ok(text_response(StatusCode::NOT_FOUND, "not found\n"))
}

fn text_response(status: StatusCode, response_body: &'static str) -> Response<ResponseBody> {
    let mut response = Response::new(body::boxed(Full::new(Bytes::from_static(
        response_body.as_bytes(),
    ))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}
