use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::{Body, Incoming};
use hyper::header::{CONNECTION, CONTENT_TYPE, HOST, HeaderValue, UPGRADE};
use hyper::{Method, Request, Response, StatusCode, Uri, Version, upgrade};
use hyper_util::rt::TokioIo;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info};

use super::config::{HostHeaderPolicy, UpstreamProtocol};
use super::headers;
use super::pool::{PoolCounters, PoolOverload, UpstreamPool};
use super::routes::{HttpRoute, HttpRouteTable, validate_http_path};
use crate::config::FallbackConfig;
use crate::gateway::admission::RequestLease;
use crate::gateway::body::{self, ResponseBody};
use crate::security::{ResolvedClientAddress, sanitize_client_address_headers};

#[derive(Clone)]
pub(crate) struct HttpProxyRuntime {
    routes: Arc<HashMap<String, Arc<UpstreamPool>>>,
    fallback: Arc<HashMap<String, Arc<UpstreamPool>>>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
}

impl HttpProxyRuntime {
    pub(crate) async fn new(
        routes: &HttpRouteTable,
        fallback: Option<&FallbackConfig>,
        max_connections: usize,
        connect_timeout: Duration,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let tasks = TaskTracker::new();
        let capacity = Arc::new(Semaphore::new(max_connections));
        let counters = Arc::new(PoolCounters::default());
        let mut route_pools = HashMap::new();
        let mut fallback_pools = HashMap::new();
        for route in routes.enabled_routes() {
            let pool = UpstreamPool::new(
                route.upstream.clone(),
                &route.host,
                Arc::clone(&capacity),
                connect_timeout,
                shutdown.child_token(),
                tasks.clone(),
                Arc::clone(&counters),
            )
            .await?;
            route_pools.insert(route.id.clone(), pool);
        }
        if let Some(fallback) = fallback {
            for host in fallback.hosts() {
                let pool = UpstreamPool::new(
                    fallback.upstream().clone(),
                    host,
                    Arc::clone(&capacity),
                    connect_timeout,
                    shutdown.child_token(),
                    tasks.clone(),
                    Arc::clone(&counters),
                )
                .await?;
                fallback_pools.insert(host.clone(), pool);
            }
        }
        let pools: Vec<_> = route_pools.values().chain(fallback_pools.values()).cloned().collect();
        let maintenance_shutdown = shutdown.child_token();
        let maintenance = tasks.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut ticks = 0u8;
            loop {
                tokio::select! {
                    () = maintenance_shutdown.cancelled() => { for pool in &pools { pool.reap_idle(); } break; }
                    _ = interval.tick() => {
                        for pool in &pools { pool.reap_idle(); }
                        ticks += 1;
                        if ticks == 6 {
                            ticks = 0;
                            info!(event = "http_pool_summary", opened_connections = counters.opened.load(Ordering::Relaxed),
                                reused_requests = counters.reused.load(Ordering::Relaxed), capacity_rejections = counters.rejected.load(Ordering::Relaxed),
                                available_connections = capacity.available_permits(), max_connections, pools = pools.len(), "HTTP upstream aggregate counters");
                        }
                    }
                }
            }
        });
        drop(maintenance);
        Ok(Self {
            routes: Arc::new(route_pools),
            fallback: Arc::new(fallback_pools),
            shutdown,
            tasks,
        })
    }

    pub(crate) async fn proxy_route(
        &self,
        request: Request<Incoming>,
        route: Arc<HttpRoute>,
        address: ResolvedClientAddress,
    ) -> Response<ResponseBody> {
        let target = match route.rewrite_target(request.uri()) {
            Ok(target) => target,
            Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid path\n"),
        };
        match self.routes.get(&route.id) {
            Some(pool) => self.proxy(request, Arc::clone(pool), target, address).await,
            None => text_response(StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable\n"),
        }
    }
    pub(crate) async fn proxy_fallback(
        &self,
        request: Request<Incoming>,
        host: &str,
        address: ResolvedClientAddress,
    ) -> Response<ResponseBody> {
        if validate_http_path(request.uri().path()).is_err() {
            return text_response(StatusCode::BAD_REQUEST, "invalid path\n");
        }
        let target = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .to_owned();
        match self.fallback.get(host) {
            Some(pool) => self.proxy(request, Arc::clone(pool), target, address).await,
            None => text_response(StatusCode::NOT_FOUND, "not found\n"),
        }
    }

    async fn proxy(
        &self,
        mut request: Request<Incoming>,
        pool: Arc<UpstreamPool>,
        target: String,
        address: ResolvedClientAddress,
    ) -> Response<ResponseBody> {
        if self.shutdown.is_cancelled() {
            return text_response(StatusCode::SERVICE_UNAVAILABLE, "gateway shutting down\n");
        }
        if request.method() == Method::CONNECT {
            return text_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "CONNECT requires an explicit WebSocket route\n",
            );
        }
        let downstream_version = request.version();
        let is_upgrade = is_http1_upgrade(&request);
        if request.headers().contains_key(UPGRADE)
            && (!is_upgrade
                || request.method() != Method::GET
                || request.headers().get_all(UPGRADE).iter().count() != 1
                || !request
                    .headers()
                    .get(UPGRADE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
                || request
                    .headers()
                    .get("sec-websocket-version")
                    .and_then(|value| value.to_str().ok())
                    != Some("13")
                || request.headers().get_all("sec-websocket-key").iter().count() != 1
                || !request.body().is_end_stream())
        {
            return text_response(
                StatusCode::BAD_REQUEST,
                "only WebSocket HTTP Upgrade is supported\n",
            );
        }
        if is_upgrade && pool.config.protocol != UpstreamProtocol::Http1 {
            return text_response(
                StatusCode::BAD_REQUEST,
                "HTTP Upgrade requires an HTTP/1 upstream\n",
            );
        }
        let authority = match headers::request_authority(&request) {
            Ok(authority) => authority,
            Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid authority\n"),
        };
        let upstream_authority = match pool.config.host_header {
            HostHeaderPolicy::Preserve => &authority,
            HostHeaderPolicy::Backend => &pool.config.authority,
        };
        let upstream_uri = match pool.config.protocol {
            UpstreamProtocol::Http1 => target.parse::<Uri>(),
            UpstreamProtocol::Http2 => format!(
                "{}://{upstream_authority}{target}",
                if pool.config.tls { "https" } else { "http" }
            )
            .parse::<Uri>(),
        };
        let upstream_uri = match upstream_uri {
            Ok(uri) => uri,
            Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid request target\n"),
        };
        let response_can_have_body = request.method() != Method::HEAD;
        let request_declared_trailers = if pool.config.protocol == UpstreamProtocol::Http1 {
            match headers::declared_trailer_names(request.headers()) {
                Ok(names) => Some(names),
                Err(_) => {
                    return text_response(StatusCode::BAD_REQUEST, "invalid Trailer declaration\n");
                }
            }
        } else {
            None
        };
        let force_chunked = pool.config.protocol == UpstreamProtocol::Http1
            && ((downstream_version == Version::HTTP_2 && !request.body().is_end_stream())
                || request.headers().contains_key("trailer")
                || (!request.body().is_end_stream()
                    && request.body().size_hint().exact().is_none()));
        let expected_upgrade = request.headers().get(UPGRADE).cloned();
        let downstream_upgrade = if is_upgrade {
            Some(upgrade::on(&mut request))
        } else {
            None
        };
        let admission = request.extensions().get::<Arc<RequestLease>>().cloned();
        let exchange = match pool.begin_exchange(admission, request.body().is_end_stream()) {
            Ok(exchange) => exchange,
            Err(_) => {
                return text_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "upstream capacity reached\n",
                );
            }
        };
        headers::sanitize_request(request.headers_mut(), is_upgrade);
        sanitize_client_address_headers(request.headers_mut(), address);
        if let Ok(value) = HeaderValue::from_str(&authority) {
            request.headers_mut().insert("x-forwarded-host", value);
        }
        *request.uri_mut() = upstream_uri;
        *request.version_mut() = match pool.config.protocol {
            UpstreamProtocol::Http1 => Version::HTTP_11,
            UpstreamProtocol::Http2 => Version::HTTP_2,
        };
        match pool.config.protocol {
            UpstreamProtocol::Http1 => {
                let value = match HeaderValue::from_str(upstream_authority) {
                    Ok(value) => value,
                    Err(_) => {
                        return text_response(StatusCode::BAD_GATEWAY, "invalid upstream host\n");
                    }
                };
                request.headers_mut().insert(HOST, value);
                if !is_upgrade {
                    request.headers_mut().insert(CONNECTION, HeaderValue::from_static("TE"));
                }
                if force_chunked {
                    request.headers_mut().remove("content-length");
                    request
                        .headers_mut()
                        .insert("transfer-encoding", HeaderValue::from_static("chunked"));
                }
            }
            UpstreamProtocol::Http2 => {
                request.headers_mut().remove(HOST);
            }
        }
        // Body and admission leases remain alive in both directions, including early responses.
        let request = request.map(|incoming| {
            pool.wrap_upload(
                incoming,
                Arc::clone(&exchange),
                force_chunked,
                request_declared_trailers,
            )
        });
        let send = async {
            match pool.config.protocol {
                UpstreamProtocol::Http1 => {
                    let mut connection = pool.acquire_http1().await?;
                    pool.wait_http1_ready(&mut connection).await?;
                    let response = connection
                        .sender
                        .send_request(request)
                        .await
                        .context("HTTP/1 upstream request failed")?;
                    Ok::<_, anyhow::Error>((response, Some(connection), None))
                }
                UpstreamProtocol::Http2 => {
                    let (response, control) = pool.send_http2(request).await?;
                    Ok((response, None, Some(control)))
                }
            }
        };
        let result = tokio::select! {
            () = self.shutdown.cancelled() => { exchange.cancel(); return text_response(StatusCode::SERVICE_UNAVAILABLE, "gateway shutting down\n"); }
            result = timeout(pool.config.pool.response_header_timeout, send) => result,
        };
        let (mut response, connection, control) = match result {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                exchange.cancel();
                if error.is::<PoolOverload>() {
                    pool.counters.rejected.fetch_add(1, Ordering::Relaxed);
                }
                debug!(backend = %pool.config.endpoint, %error, "HTTP upstream request failed (no automatic retry)");
                return text_response(
                    if error.is::<PoolOverload>() {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::BAD_GATEWAY
                    },
                    "upstream unavailable\n",
                );
            }
            Err(_) => {
                exchange.cancel();
                return text_response(StatusCode::GATEWAY_TIMEOUT, "upstream response timeout\n");
            }
        };
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let accepted = response.headers().get(UPGRADE);
            let connection_upgrade = response
                .headers()
                .get_all(CONNECTION)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .any(|value| value.trim().eq_ignore_ascii_case("upgrade"));
            let same_protocol = accepted
                .and_then(|value| value.to_str().ok())
                .zip(expected_upgrade.as_ref().and_then(|value| value.to_str().ok()))
                .is_some_and(|(accepted, offered)| accepted.eq_ignore_ascii_case(offered));
            if !is_upgrade
                || !same_protocol
                || !connection_upgrade
                || response.headers().get_all(UPGRADE).iter().count() != 1
            {
                return text_response(StatusCode::BAD_GATEWAY, "invalid upstream upgrade\n");
            }
            let (Some(downstream), Some(connection)) = (downstream_upgrade, connection) else {
                return text_response(StatusCode::BAD_GATEWAY, "invalid upstream upgrade\n");
            };
            let upstream = upgrade::on(&mut response);
            let shutdown = self.shutdown.child_token();
            let task = self.tasks.spawn(async move {
                let _connection = connection; // Retains upstream capacity across raw Upgrade.
                let _exchange = exchange;
                let establish = async {
                    let (downstream, upstream) = tokio::try_join!(downstream, upstream)?;
                    Ok::<_, hyper::Error>((TokioIo::new(downstream), TokioIo::new(upstream)))
                };
                let connected = tokio::select! {
                    () = shutdown.cancelled() => return,
                    result = timeout(Duration::from_secs(10), establish) => result,
                };
                if let Ok(Ok((mut downstream, mut upstream))) = connected {
                    tokio::select! {
                        () = shutdown.cancelled() => {}
                        result = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => { if let Err(error) = result { debug!(%error, "HTTP upgraded tunnel closed"); } }
                    }
                }
            });
            drop(task);
            headers::sanitize_response(response.headers_mut(), true);
            *response.version_mut() = downstream_version;
            return response.map(body::boxed);
        }
        headers::sanitize_response(response.headers_mut(), false);
        let response_declared_trailers = if downstream_version != Version::HTTP_2 {
            match headers::declared_trailer_names(response.headers()) {
                Ok(names) => Some(names),
                Err(_) => {
                    return text_response(
                        StatusCode::BAD_GATEWAY,
                        "invalid upstream Trailer declaration\n",
                    );
                }
            }
        } else {
            None
        };
        let response_force_chunked = downstream_version == Version::HTTP_11
            && response_can_have_body
            && response.headers().contains_key("trailer")
            && !response.body().is_end_stream();
        if response_force_chunked {
            response.headers_mut().remove("content-length");
        }
        *response.version_mut() = downstream_version;
        response.map(|incoming| {
            pool.wrap_response(
                incoming,
                exchange,
                connection,
                control,
                response_declared_trailers,
                response_force_chunked,
            )
        })
    }

    pub(crate) fn close(&self) {
        self.shutdown.cancel();
        self.tasks.close();
    }
    pub(crate) async fn wait(&self) {
        self.tasks.wait().await;
    }
}

fn is_http1_upgrade<B>(request: &Request<B>) -> bool {
    request.version() == Version::HTTP_11
        && request.headers().contains_key(UPGRADE)
        && request
            .headers()
            .get_all(CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
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
