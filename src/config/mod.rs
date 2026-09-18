use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::routes::{RouteError, RouteSpec, RouteTable};

const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_WEBSOCKET_UPGRADE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_BACKEND_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_SHUTDOWN_GRACE_SECONDS: u64 = 30;
const DEFAULT_MAX_WEBSOCKET_MESSAGE_SIZE_BYTES: usize = 1024 * 1024;

const MAX_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 300;
const MAX_WEBSOCKET_UPGRADE_TIMEOUT_SECONDS: u64 = 300;
const MAX_BACKEND_CONNECT_TIMEOUT_SECONDS: u64 = 300;
const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 600;
const MAX_WEBSOCKET_MESSAGE_SIZE_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct Config {
    server: ServerConfig,
    tls: TlsConfig,
    routes: Arc<RouteTable>,
}

impl Config {
    pub(crate) async fn load(path: &Path) -> Result<Self, ConfigError> {
        let source = tokio::fs::read_to_string(path).await.map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        let file_config =
            toml::from_str::<FileConfig>(&source).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?;

        file_config.validate()
    }

    pub(crate) fn into_parts(self) -> (ServerConfig, TlsConfig, Arc<RouteTable>) {
        (self.server, self.tls, self.routes)
    }
}

pub(crate) struct ServerConfig {
    listen: SocketAddr,
    tls_handshake_timeout: Duration,
    websocket_upgrade_timeout: Duration,
    backend_connect_timeout: Duration,
    shutdown_grace: Duration,
    max_websocket_message_size: usize,
}

impl ServerConfig {
    pub(crate) fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub(crate) fn tls_handshake_timeout(&self) -> Duration {
        self.tls_handshake_timeout
    }

    pub(crate) fn websocket_upgrade_timeout(&self) -> Duration {
        self.websocket_upgrade_timeout
    }

    pub(crate) fn backend_connect_timeout(&self) -> Duration {
        self.backend_connect_timeout
    }

    pub(crate) fn shutdown_grace(&self) -> Duration {
        self.shutdown_grace
    }

    pub(crate) fn max_websocket_message_size(&self) -> usize {
        self.max_websocket_message_size
    }
}

pub(crate) struct TlsConfig {
    cert: PathBuf,
    key: PathBuf,
}

impl TlsConfig {
    pub(crate) fn cert(&self) -> &Path {
        &self.cert
    }

    pub(crate) fn key(&self) -> &Path {
        &self.key
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    server: FileServerConfig,
    tls: FileTlsConfig,
    #[serde(default)]
    routes: Vec<FileRouteConfig>,
}

impl FileConfig {
    fn validate(self) -> Result<Config, ConfigError> {
        let tls_handshake_timeout = validate_seconds(
            "server.tls_handshake_timeout_seconds",
            self.server.tls_handshake_timeout_seconds,
            MAX_TLS_HANDSHAKE_TIMEOUT_SECONDS,
        )?;
        let websocket_upgrade_timeout = validate_seconds(
            "server.websocket_upgrade_timeout_seconds",
            self.server.websocket_upgrade_timeout_seconds,
            MAX_WEBSOCKET_UPGRADE_TIMEOUT_SECONDS,
        )?;
        let backend_connect_timeout = validate_seconds(
            "server.backend_connect_timeout_seconds",
            self.server.backend_connect_timeout_seconds,
            MAX_BACKEND_CONNECT_TIMEOUT_SECONDS,
        )?;
        let shutdown_grace = validate_seconds(
            "server.shutdown_grace_seconds",
            self.server.shutdown_grace_seconds,
            MAX_SHUTDOWN_GRACE_SECONDS,
        )?;
        let max_websocket_message_size = validate_size(
            "server.max_websocket_message_size_bytes",
            self.server.max_websocket_message_size_bytes,
            MAX_WEBSOCKET_MESSAGE_SIZE_BYTES,
        )?;

        validate_path("tls.cert", &self.tls.cert)?;
        validate_path("tls.key", &self.tls.key)?;

        let route_specs = self
            .routes
            .into_iter()
            .map(|route| RouteSpec {
                id: route.id,
                path: route.path,
                backend: route.backend,
                enabled: route.enabled,
            })
            .collect();
        let routes = Arc::new(RouteTable::build(route_specs)?);

        Ok(Config {
            server: ServerConfig {
                listen: self.server.listen,
                tls_handshake_timeout,
                websocket_upgrade_timeout,
                backend_connect_timeout,
                shutdown_grace,
                max_websocket_message_size,
            },
            tls: TlsConfig {
                cert: self.tls.cert,
                key: self.tls.key,
            },
            routes,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileServerConfig {
    listen: SocketAddr,
    #[serde(default = "default_tls_handshake_timeout_seconds")]
    tls_handshake_timeout_seconds: u64,
    #[serde(default = "default_websocket_upgrade_timeout_seconds")]
    websocket_upgrade_timeout_seconds: u64,
    #[serde(default = "default_backend_connect_timeout_seconds")]
    backend_connect_timeout_seconds: u64,
    #[serde(default = "default_shutdown_grace_seconds")]
    shutdown_grace_seconds: u64,
    #[serde(default = "default_max_websocket_message_size_bytes")]
    max_websocket_message_size_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTlsConfig {
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRouteConfig {
    id: String,
    path: String,
    backend: String,
    #[serde(default = "default_route_enabled")]
    enabled: bool,
}

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("failed to read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse configuration file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error("invalid route configuration: {0}")]
    Route(#[from] RouteError),
}

fn validate_seconds(
    field: &'static str,
    seconds: u64,
    maximum: u64,
) -> Result<Duration, ConfigError> {
    if seconds == 0 {
        return Err(ConfigError::Invalid(format!(
            "{field} must be greater than zero"
        )));
    }
    if seconds > maximum {
        return Err(ConfigError::Invalid(format!(
            "{field} must not exceed {maximum} seconds"
        )));
    }

    Ok(Duration::from_secs(seconds))
}

fn validate_size(field: &'static str, value: usize, maximum: usize) -> Result<usize, ConfigError> {
    if value == 0 {
        return Err(ConfigError::Invalid(format!(
            "{field} must be greater than zero"
        )));
    }
    if value > maximum {
        return Err(ConfigError::Invalid(format!(
            "{field} must not exceed {maximum} bytes"
        )));
    }

    Ok(value)
}

fn validate_path(field: &'static str, path: &Path) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::Invalid(format!("{field} must not be empty")));
    }

    Ok(())
}

const fn default_tls_handshake_timeout_seconds() -> u64 {
    DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS
}

const fn default_websocket_upgrade_timeout_seconds() -> u64 {
    DEFAULT_WEBSOCKET_UPGRADE_TIMEOUT_SECONDS
}

const fn default_backend_connect_timeout_seconds() -> u64 {
    DEFAULT_BACKEND_CONNECT_TIMEOUT_SECONDS
}

const fn default_shutdown_grace_seconds() -> u64 {
    DEFAULT_SHUTDOWN_GRACE_SECONDS
}

const fn default_max_websocket_message_size_bytes() -> usize {
    DEFAULT_MAX_WEBSOCKET_MESSAGE_SIZE_BYTES
}

const fn default_route_enabled() -> bool {
    true
}
