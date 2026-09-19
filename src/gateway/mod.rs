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
    let (server, tls, observability, routes, grpc_routes) = config.into_parts();
    listener::run(server, tls, observability, routes, grpc_routes, shutdown).await
}
