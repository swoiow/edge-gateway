use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue, UPGRADE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnectionBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::acme::{AcmeManager, AcmeRuntime};
use crate::config::{AcmeConfig, FallbackConfig, ObservabilityConfig, ServerConfig, TlsConfig};
use crate::gateway::admission::RequestLease;
use crate::gateway::body::{self, ResponseBody};
use crate::gateway::websocket::WebSocketRuntime;
use crate::grpc::{GrpcRouteTable, GrpcRuntime};
use crate::http_proxy::routes::validate_http_path;
use crate::http_proxy::{HttpProxyRuntime, HttpRouteTable};
use crate::observability::{ActiveConnection, AdmissionRejection, RuntimeObservability};
use crate::routes::RouteTable;
use crate::routing::{RoutingPolicy, resolve_request_host};
use crate::security::ClientAddressPolicy;
use crate::tls::{CertificateStore, build_acceptor};

pub(super) async fn run<F>(
    server_config: ServerConfig,
    routing: Arc<RoutingPolicy>,
    client_address: Arc<ClientAddressPolicy>,
    tls_config: TlsConfig,
    acme_config: AcmeConfig,
    observability_config: ObservabilityConfig,
    fallback_config: Option<FallbackConfig>,
    routes: Arc<RouteTable>,
    grpc_routes: Arc<GrpcRouteTable>,
    http_routes: Arc<HttpRouteTable>,
    max_http_upstream_connections: usize,
    shutdown_signal: F,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let certificate_store = CertificateStore::load(tls_config.clone()).await?;
    let mut acme_manager = if acme_config.enabled() {
        Some(AcmeManager::new(
            acme_config.clone(),
            tls_config,
            certificate_store.clone(),
        ))
    } else {
        None
    };
    if let Some(manager) = acme_manager.as_mut() {
        manager.bootstrap_if_store_empty().await?;
    }
    if certificate_store.is_empty() {
        bail!(
            "TLS certificate directory contains no usable certificate pairs and ACME did not provision one"
        );
    }
    if !certificate_store.default_certificate_available() {
        let pending_managed_default = certificate_store
            .config()
            .default_certificate()
            .is_some_and(|id| acme_config.enabled() && acme_config.manages_certificate(id));
        if pending_managed_default {
            warn!(
                default_certificate = ?certificate_store.config().default_certificate(),
                "configured default TLS certificate is pending ACME issuance; existing SNI certificates remain available"
            );
        } else {
            bail!("tls.default_certificate does not identify a loaded certificate");
        }
    }

    let tls_acceptor = build_acceptor(&certificate_store);
    let listener = TcpListener::bind(server_config.listen())
        .await
        .with_context(|| format!("failed to bind listener on {}", server_config.listen()))?;

    let server_config = Arc::new(server_config);
    let cancellation = CancellationToken::new();
    let observability_shutdown = CancellationToken::new();
    let (observability, observability_task) =
        RuntimeObservability::start(observability_config, observability_shutdown.child_token())
            .await?;
    let websocket_runtime = WebSocketRuntime::new(
        Arc::clone(&server_config),
        cancellation.child_token(),
        observability.clone(),
        Arc::clone(client_address.ip_blocking()),
    );
    let grpc_runtime = GrpcRuntime::new(
        grpc_routes,
        server_config.backend_connect_timeout(),
        server_config.max_grpc_concurrent_streams_per_backend(),
        cancellation.child_token(),
        observability.clone(),
    );
    let http_runtime = HttpProxyRuntime::new(
        &http_routes,
        fallback_config.as_ref(),
        max_http_upstream_connections,
        server_config.backend_connect_timeout(),
        cancellation.child_token(),
    )
    .await?;
    let client_address_task = client_address.start(cancellation.child_token());
    let mut ip_blocking_task = client_address.ip_blocking().start(cancellation.child_token());
    let transport_capacity = Arc::new(Semaphore::new(server_config.max_connections()));
    let handshake_capacity = Arc::new(Semaphore::new(
        server_config.max_concurrent_tls_handshakes(),
    ));
    let request_capacity = Arc::new(Semaphore::new(server_config.max_active_requests()));
    let service_state = ServiceState {
        routing,
        client_address,
        server_config: Arc::clone(&server_config),
        request_capacity,
        observability: observability.clone(),
        routes: Arc::clone(&routes),
        websocket: websocket_runtime.clone(),
        grpc: grpc_runtime.clone(),
        fallback: fallback_config.clone(),
        http_routes: Arc::clone(&http_routes),
        http: http_runtime.clone(),
    };
    let acme_runtime = acme_manager
        .take()
        .map(|manager| AcmeRuntime::start(manager, cancellation.child_token()));

    info!(
        listen = %server_config.listen(),
        configured_websocket_routes = routes.configured_count(),
        enabled_websocket_routes = routes.enabled_count(),
        configured_grpc_routes = grpc_runtime.configured_route_count(),
        enabled_grpc_routes = grpc_runtime.enabled_route_count(),
        tls_certificates = certificate_store.certificate_count(),
        acme_enabled = acme_config.enabled(),
        fallback_enabled = fallback_config.is_some(),
        configured_http_routes = http_routes.configured_count(),
        enabled_http_routes = http_routes.enabled_count(),
        "gateway listener started"
    );

    let mut connections = JoinSet::new();
    let mut listener_failure = None;
    let mut block_manager_finished = false;
    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            biased;

            () = &mut shutdown_signal => {
                info!("shutdown signal received; stopping listener");
                break;
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(error = %error, "connection task terminated unexpectedly");
                }
            }
            completed = &mut ip_blocking_task => {
                block_manager_finished = true;
                listener_failure = Some(match completed {
                    Ok(()) => anyhow::anyhow!("IP block manager stopped before listener shutdown"),
                    Err(error) => anyhow::anyhow!("IP block manager failed: {error}"),
                });
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        listener_failure = Some(anyhow::Error::new(error).context("failed to accept TCP connection"));
                        break;
                    }
                };
                let transport_permit = match Arc::clone(&transport_capacity).try_acquire_owned() {
                    Ok(permit) => Arc::new(permit),
                    Err(_) => { log_admission_rejection(&observability, AdmissionRejection::ConnectionCapacity, peer); continue; }
                };
                let handshake_permit = match Arc::clone(&handshake_capacity).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => { log_admission_rejection(&observability, AdmissionRejection::HandshakeCapacity, peer); continue; }
                };
                let (transport_connection_id, active_connection) =
                    observability.begin_transport_connection();
                let acceptor = tls_acceptor.clone();
                let connection_cancellation = cancellation.child_token();
                let handshake_timeout = server_config.tls_handshake_timeout();
                let shutdown_grace = server_config.shutdown_grace();
                let state = service_state.clone();
                let connection_observability = observability.clone();

                let parameters = ConnectionParameters {
                    transport_permit,
                    handshake_permit,
                    acceptor,
                    cancellation: connection_cancellation,
                    handshake_timeout,
                    shutdown_grace,
                    peer,
                    transport_connection_id,
                    active_connection,
                    state,
                    observability: connection_observability,
                };
                connections.spawn(async move {
                    serve_connection(stream, parameters).await;
                });
            }
        }
    }

    cancellation.cancel();
    websocket_runtime.close();
    grpc_runtime.close();
    http_runtime.close();

    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            warn!(error = %error, "connection task terminated unexpectedly during shutdown");
        }
    }

    let data_plane_shutdown = async {
        tokio::join!(
            websocket_runtime.wait(),
            grpc_runtime.wait(),
            http_runtime.wait()
        );
    };
    if timeout(server_config.shutdown_grace(), data_plane_shutdown).await.is_err() {
        warn!(
            timeout_seconds = server_config.shutdown_grace().as_secs(),
            "data-plane tasks exceeded shutdown grace period"
        );
    }

    if let Some(runtime) = acme_runtime {
        runtime.wait().await;
    }

    if let Err(error) = client_address_task.await {
        warn!(%error, "CF maintenance task terminated unexpectedly");
    }
    if !block_manager_finished && let Err(error) = ip_blocking_task.await {
        warn!(%error, "IP block manager terminated unexpectedly");
    }
    observability_shutdown.cancel();
    observability_task.wait().await;
    info!("gateway shutdown complete");
    if let Some(error) = listener_failure {
        return Err(error);
    }
    Ok(())
}

#[derive(Clone)]
struct ServiceState {
    routing: Arc<RoutingPolicy>,
    client_address: Arc<ClientAddressPolicy>,
    server_config: Arc<ServerConfig>,
    request_capacity: Arc<Semaphore>,
    observability: RuntimeObservability,
    routes: Arc<RouteTable>,
    websocket: WebSocketRuntime,
    grpc: GrpcRuntime,
    fallback: Option<FallbackConfig>,
    http_routes: Arc<HttpRouteTable>,
    http: HttpProxyRuntime,
}

struct ConnectionParameters {
    transport_permit: Arc<OwnedSemaphorePermit>,
    handshake_permit: OwnedSemaphorePermit,
    acceptor: TlsAcceptor,
    cancellation: CancellationToken,
    handshake_timeout: Duration,
    shutdown_grace: Duration,
    peer: std::net::SocketAddr,
    transport_connection_id: u64,
    active_connection: ActiveConnection,
    state: ServiceState,
    observability: RuntimeObservability,
}

async fn serve_connection(stream: TcpStream, parameters: ConnectionParameters) {
    let ConnectionParameters {
        transport_permit,
        handshake_permit,
        acceptor,
        cancellation,
        handshake_timeout,
        shutdown_grace,
        peer,
        transport_connection_id,
        active_connection,
        state,
        observability,
    } = parameters;
    let connection_started = Instant::now();
    let handshake_started = Instant::now();
    let tls_stream = match timeout(handshake_timeout, acceptor.accept(stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            observability.record_tls_handshake_failure();
            warn!(
                transport_connection_id,
                %peer,
                handshake_duration_ms = handshake_started.elapsed().as_millis(),
                active_transport_connections = active_connection.active_connections(),
                error = %error,
                "TLS handshake failed"
            );
            return;
        }
        Err(_) => {
            observability.record_tls_handshake_timeout();
            warn!(
                transport_connection_id,
                %peer,
                timeout_seconds = handshake_timeout.as_secs(),
                handshake_duration_ms = handshake_started.elapsed().as_millis(),
                active_transport_connections = active_connection.active_connections(),
                "TLS handshake timed out"
            );
            return;
        }
    };
    drop(handshake_permit);
    observability.record_tls_handshake_success();

    let downstream_sni = tls_stream.get_ref().1.server_name().map(str::to_owned);
    let alpn = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
        .unwrap_or_else(|| "none".to_owned());
    if observability.connection_event_logs_enabled() {
        info!(
            transport_connection_id,
            %peer,
            %alpn,
            handshake_duration_ms = handshake_started.elapsed().as_millis(),
            active_transport_connections = active_connection.active_connections(),
            "Cloudflare-facing TLS connection established"
        );
    } else {
        debug!(
            transport_connection_id,
            %peer,
            %alpn,
            handshake_duration_ms = handshake_started.elapsed().as_millis(),
            active_transport_connections = active_connection.active_connections(),
            "Cloudflare-facing TLS connection established"
        );
    }

    let request_count = Arc::new(AtomicU64::new(0));
    let service_request_count = Arc::clone(&request_count);
    let service_downstream_sni = downstream_sni.clone();
    let connection_server_config = Arc::clone(&state.server_config);
    let service = service_fn(move |request| {
        service_request_count.fetch_add(1, Ordering::Relaxed);
        handle_request(
            request,
            state.clone(),
            peer,
            transport_connection_id,
            service_downstream_sni.clone(),
            Arc::clone(&transport_permit),
        )
    });
    let io = TokioIo::new(tls_stream);
    let mut builder = AutoConnectionBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(connection_server_config.http_header_read_timeout())
        .max_buf_size(connection_server_config.max_http_header_bytes());
    // Preserve Hyper's stack-allocated default header parser when using 100.
    if connection_server_config.max_http_header_count() != 100 {
        builder.http1().max_headers(connection_server_config.max_http_header_count());
    }
    builder
        .http2()
        .enable_connect_protocol()
        .max_concurrent_streams(connection_server_config.max_http2_concurrent_streams() as u32)
        .max_header_list_size(connection_server_config.max_http_header_bytes() as u32)
        .max_send_buf_size(connection_server_config.max_http2_send_buffer_bytes());
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);

    let close_reason = tokio::select! {
        result = &mut connection => {
            match result {
                Ok(()) => "peer_closed",
                Err(error) => {
                    observability.record_http_connection_error();
                    debug!(
                        transport_connection_id,
                        %peer,
                        error = %error,
                        "HTTP connection closed with an error"
                    );
                    "http_error"
                }
            }
        }
        () = cancellation.cancelled() => {
            connection.as_mut().graceful_shutdown();

            match timeout(shutdown_grace, &mut connection).await {
                Ok(Ok(())) => "gateway_shutdown",
                Ok(Err(error)) => {
                    observability.record_http_connection_error();
                    debug!(
                        transport_connection_id,
                        %peer,
                        error = %error,
                        "HTTP connection failed during graceful shutdown"
                    );
                    "shutdown_error"
                }
                Err(_) => {
                    warn!(
                        transport_connection_id,
                        %peer,
                        timeout_seconds = shutdown_grace.as_secs(),
                        "HTTP connection exceeded shutdown grace period"
                    );
                    "shutdown_timeout"
                }
            }
        }
    };

    let duration_ms = connection_started.elapsed().as_millis();
    let remaining_active = active_connection.active_connections().saturating_sub(1);
    if observability.connection_event_logs_enabled() {
        info!(
            transport_connection_id,
            %peer,
            %alpn,
            close_reason,
            request_count = request_count.load(Ordering::Relaxed),
            duration_ms,
            active_transport_connections = remaining_active,
            "Cloudflare-facing HTTP connection closed"
        );
    } else {
        debug!(
            transport_connection_id,
            %peer,
            %alpn,
            close_reason,
            request_count = request_count.load(Ordering::Relaxed),
            duration_ms,
            active_transport_connections = remaining_active,
            "Cloudflare-facing HTTP connection closed"
        );
    }
}

async fn handle_request(
    mut request: Request<Incoming>,
    state: ServiceState,
    peer: std::net::SocketAddr,
    transport_connection_id: u64,
    downstream_sni: Option<String>,
    transport_permit: Arc<OwnedSemaphorePermit>,
) -> std::result::Result<Response<ResponseBody>, Infallible> {
    if request.method() == Method::GET
        && matches!(request.uri().path(), "/health/live" | "/health/ready")
    {
        // Only explicit health peers bypass CF header resolution and domain routing.
        return Ok(if state.client_address.permits_health_peer(peer) {
            text_response(StatusCode::OK, "ok\n")
        } else {
            log_admission_rejection(&state.observability, AdmissionRejection::OriginPeer, peer);
            text_response(StatusCode::FORBIDDEN, "forbidden\n")
        });
    }
    let host = match resolve_request_host(&request) {
        Ok(host) => host,
        Err(_) => {
            log_admission_rejection(&state.observability, AdmissionRejection::Authority, peer);
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "invalid authority\n",
            ));
        }
    };
    if !state.routing.permits_request_host(&host, downstream_sni.as_deref()) {
        log_admission_rejection(&state.observability, AdmissionRejection::Authority, peer);
        return Ok(text_response(
            StatusCode::MISDIRECTED_REQUEST,
            "misdirected request\n",
        ));
    }
    if validate_http_path(request.uri().path()).is_err() {
        return Ok(text_response(StatusCode::BAD_REQUEST, "invalid path\n"));
    }
    // Select the route before applying its origin policy, on every H2 stream.
    let path = request.uri().path();
    let websocket_route = state.routes.resolve(&host, path);
    let grpc_route = if websocket_route.is_none() {
        state.grpc.resolve(&host, path)
    } else {
        None
    };
    let http_route = if websocket_route.is_none() && grpc_route.is_none() {
        state.http_routes.resolve(&host, path)
    } else {
        None
    };
    let fallback = state.fallback.as_ref().filter(|fallback| fallback.permits_host(&host));
    let security = if let Some(route) = &websocket_route {
        route.security()
    } else if let Some(route) = &grpc_route {
        route.security()
    } else if let Some(route) = &http_route {
        route.security
    } else if let Some(fallback) = fallback {
        fallback.security()
    } else {
        crate::security::RouteSecurity::default()
    };
    let client_address =
        match state.client_address.resolve_client_address(peer, request.headers(), security) {
            Ok(address) => address,
            Err(_) => {
                log_admission_rejection(
                    &state.observability,
                    AdmissionRejection::ClientIdentity,
                    peer,
                );
                return Ok(text_response(StatusCode::FORBIDDEN, "forbidden\n"));
            }
        };
    let blocking = state.client_address.ip_blocking();
    if blocking.is_client_ip_blocked(client_address) {
        return Ok(
            if grpc_route.is_some() && request.version() == Version::HTTP_2 {
                crate::grpc::blocked_grpc_response()
            } else {
                text_response(StatusCode::FORBIDDEN, "forbidden\n")
            },
        );
    }
    let header_bytes = request.headers().iter().fold(0usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(32)
    });
    if request.headers().len() > state.server_config.max_http_header_count()
        || header_bytes > state.server_config.max_http_header_bytes()
    {
        log_admission_rejection(&state.observability, AdmissionRejection::Headers, peer);
        if websocket_route.is_some() || grpc_route.is_some() {
            blocking.record_client_protocol_violation(
                client_address,
                crate::security::ViolationRule::SizeViolation,
            );
        }
        return Ok(text_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers too large\n",
        ));
    }
    if websocket_route.is_none()
        && grpc_route.is_none()
        && http_route.is_none()
        && fallback.is_none()
    {
        if blocking.is_scan_namespace(path) {
            blocking.record_client_protocol_violation(
                client_address,
                crate::security::ViolationRule::NamespaceScan,
            );
        }
        return Ok(text_response(StatusCode::NOT_FOUND, "not found\n"));
    }
    if grpc_route.is_some()
        && let Some(response) = crate::grpc::reject_invalid_grpc_request(&request)
    {
        blocking.record_client_protocol_violation(
            client_address,
            crate::security::ViolationRule::InvalidGrpc,
        );
        return Ok(response);
    }
    let request_permit = match Arc::clone(&state.request_capacity).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            log_admission_rejection(
                &state.observability,
                AdmissionRejection::RequestCapacity,
                peer,
            );
            if state.grpc.resolve(&host, request.uri().path()).is_some()
                && request.version() == Version::HTTP_2
            {
                let mut response = text_response(StatusCode::OK, "");
                *response.version_mut() = Version::HTTP_2;
                response
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
                response.headers_mut().insert("grpc-status", HeaderValue::from_static("8"));
                response.headers_mut().insert(
                    "grpc-message",
                    HeaderValue::from_static("gateway%20capacity%20reached"),
                );
                return Ok(response);
            }
            return Ok(text_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway capacity reached\n",
            ));
        }
    };
    let admission = RequestLease::new(request_permit, transport_permit);
    request.extensions_mut().insert(Arc::clone(&admission));
    crate::security::sanitize_client_address_headers(request.headers_mut(), client_address);

    let response = if let Some(route) = websocket_route {
        match state
            .websocket
            .accept(
                request,
                Arc::clone(&route),
                client_address,
                transport_connection_id,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                if error.is_client_protocol_violation() {
                    blocking.record_client_protocol_violation(
                        client_address,
                        crate::security::ViolationRule::InvalidWebsocket,
                    );
                }
                // Client rejections do not emit one warning per attacker request.
                debug!(transport_connection_id, route_id = route.id(), host = route.host(),
                    %peer, client_ip = %client_address.client_ip,
                    client_ip_source = client_address.client_ip_source,
                    trusted_proxy = client_address.trusted_proxy, backend_failure = error.is_backend_failure(), error = %error, "WebSocket request rejected");
                let mut response = text_response(error.status(), error.public_message());
                if error.should_advertise_http1_upgrade() {
                    response.headers_mut().insert(UPGRADE, HeaderValue::from_static("websocket"));
                }
                response
            }
        }
    } else if let Some(route) = grpc_route {
        state.grpc.proxy(request, route, client_address, transport_connection_id).await
    } else if let Some(route) = http_route {
        state.http.proxy_route(request, route, client_address).await
    } else if fallback.is_some() {
        state.http.proxy_fallback(request, &host, client_address).await
    } else {
        text_response(StatusCode::NOT_FOUND, "not found\n")
    };
    Ok(response.map(|response_body| body::with_admission(response_body, admission)))
}

fn log_admission_rejection(
    observability: &RuntimeObservability,
    reason: AdmissionRejection,
    peer: std::net::SocketAddr,
) {
    if observability.record_admission_rejection(reason) {
        warn!(%peer, reason = reason.as_str(), "gateway admission rejection (sampled)");
    }
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
