use anyhow::{Result, anyhow};
use tracing_subscriber::EnvFilter;

mod runtime;

pub(crate) use runtime::{
    ActiveConnection, RelayDirection, RuntimeObservability, WebSocketCloseClass,
};

pub(crate) fn init() -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("edge_gateway=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|error| anyhow!("failed to initialize tracing subscriber: {error}"))
}
