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
    let (server, tls, routes) = config.into_parts();
    listener::run(server, tls, routes, shutdown).await
}
