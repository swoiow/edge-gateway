pub(crate) mod admission;
pub(crate) mod body;
mod h2_websocket;
mod listener;
mod relay;
mod websocket;

use std::future::Future;

use anyhow::Result;

use crate::config::Config;

pub(crate) async fn run<F>(config: Config, shutdown: F) -> Result<()>
where
    F: Future<Output = ()>,
{
    let (
        server,
        routing,
        client_address,
        tls,
        acme,
        observability,
        fallback,
        routes,
        grpc_routes,
        http_routes,
        max_http_upstream_connections,
    ) = config.into_parts();
    listener::run(
        server,
        routing,
        client_address,
        tls,
        acme,
        observability,
        fallback,
        routes,
        grpc_routes,
        http_routes,
        max_http_upstream_connections,
        shutdown,
    )
    .await
}
