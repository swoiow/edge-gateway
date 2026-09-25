mod acme;
mod config;
mod gateway;
mod grpc;
mod observability;
mod routes;
mod tls;

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use tokio::signal;
#[cfg(unix)]
use tracing::warn;
use tracing::{error, info};

use crate::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    observability::init()?;

    let config_path = config_path()?;
    let config = Config::load(&config_path).await.with_context(|| {
        format!(
            "unable to load configuration from {}",
            config_path.display()
        )
    })?;

    info!(config = %config_path.display(), "configuration loaded");
    gateway::run(config, shutdown_signal()).await
}

fn config_path() -> Result<PathBuf> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().unwrap_or_else(|| OsString::from("config.toml"));

    if let Some(unexpected) = arguments.next() {
        bail!(
            "unexpected argument {}; usage: edge-gateway [CONFIG_PATH]",
            PathBuf::from(unexpected).display()
        );
    }

    Ok(PathBuf::from(path))
}

#[cfg(unix)]
async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();

    match signal::unix::signal(signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                result = ctrl_c => {
                    if let Err(error) = result {
                        error!(%error, "failed to listen for Ctrl+C");
                    }
                }
                signal = terminate.recv() => {
                    if signal.is_none() {
                        warn!("SIGTERM stream ended before receiving a signal");
                    }
                }
            }
        }
        Err(error) => {
            warn!(%error, "failed to install SIGTERM handler; waiting for Ctrl+C only");
            if let Err(error) = ctrl_c.await {
                error!(%error, "failed to listen for Ctrl+C");
            }
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    if let Err(error) = signal::ctrl_c().await {
        error!(%error, "failed to listen for Ctrl+C");
    }
}
