use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::grpc::{GrpcRouteError, GrpcRouteSpec, GrpcRouteTable};
use crate::routes::{RouteError, RouteSpec, RouteTable};

const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_WEBSOCKET_UPGRADE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_BACKEND_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_SHUTDOWN_GRACE_SECONDS: u64 = 30;
const DEFAULT_MAX_WEBSOCKET_MESSAGE_SIZE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_GRPC_CONCURRENT_STREAMS_PER_BACKEND: usize = 256;

const MAX_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 300;
const MAX_WEBSOCKET_UPGRADE_TIMEOUT_SECONDS: u64 = 300;
const MAX_BACKEND_CONNECT_TIMEOUT_SECONDS: u64 = 300;
const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 600;
const MAX_WEBSOCKET_MESSAGE_SIZE_BYTES: usize = 64 * 1024 * 1024;
const MAX_GRPC_CONCURRENT_STREAMS_PER_BACKEND: usize = 4096;
const MAX_OBSERVABILITY_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

pub(crate) struct Config {
    server: ServerConfig,
    tls: TlsConfig,
    observability: ObservabilityConfig,
    routes: Arc<RouteTable>,
    grpc_routes: Arc<GrpcRouteTable>,
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
        let config_directory = path.parent().unwrap_or_else(|| Path::new("."));
        file_config.validate(config_directory)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ServerConfig,
        TlsConfig,
        ObservabilityConfig,
        Arc<RouteTable>,
        Arc<GrpcRouteTable>,
    ) {
        (
            self.server,
            self.tls,
            self.observability,
            self.routes,
            self.grpc_routes,
        )
    }
}

pub(crate) struct ServerConfig {
    listen: SocketAddr,
    tls_handshake_timeout: Duration,
    websocket_upgrade_timeout: Duration,
    backend_connect_timeout: Duration,
    shutdown_grace: Duration,
    max_websocket_message_size: usize,
    max_grpc_concurrent_streams_per_backend: usize,
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

    pub(crate) fn max_grpc_concurrent_streams_per_backend(&self) -> usize {
        self.max_grpc_concurrent_streams_per_backend
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

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum ObservabilityMode {
    Off,
    Production,
    Diagnostic,
}

pub(crate) struct ObservabilityConfig {
    mode: ObservabilityMode,
    summary_interval: Duration,
    summary_file: PathBuf,
    diagnostic_interval: Duration,
    diagnostic_file: PathBuf,
    connection_event_logs_enabled: bool,
}

impl ObservabilityConfig {
    pub(crate) fn mode(&self) -> ObservabilityMode {
        self.mode
    }

    pub(crate) fn summary_interval(&self) -> Duration {
        self.summary_interval
    }

    pub(crate) fn summary_file(&self) -> &Path {
        &self.summary_file
    }

    pub(crate) fn diagnostic_interval(&self) -> Duration {
        self.diagnostic_interval
    }

    pub(crate) fn diagnostic_file(&self) -> &Path {
        &self.diagnostic_file
    }

    pub(crate) fn connection_event_logs_enabled(&self) -> bool {
        self.connection_event_logs_enabled
    }

    fn off() -> Self {
        Self {
            mode: ObservabilityMode::Off,
            summary_interval: Duration::from_secs(300),
            summary_file: PathBuf::new(),
            diagnostic_interval: Duration::from_secs(60),
            diagnostic_file: PathBuf::new(),
            connection_event_logs_enabled: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    server: FileServerConfig,
    tls: FileTlsConfig,
    #[serde(default)]
    observability: Option<FileObservabilityConfig>,
    #[serde(default)]
    routes: Vec<FileRouteConfig>,
    #[serde(default)]
    grpc_routes: Vec<FileGrpcRouteConfig>,
}

impl FileConfig {
    fn validate(self, config_directory: &Path) -> Result<Config, ConfigError> {
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
        let max_grpc_concurrent_streams_per_backend = validate_count(
            "server.max_grpc_concurrent_streams_per_backend",
            self.server.max_grpc_concurrent_streams_per_backend,
            MAX_GRPC_CONCURRENT_STREAMS_PER_BACKEND,
        )?;

        validate_path("tls.cert", &self.tls.cert)?;
        validate_path("tls.key", &self.tls.key)?;

        let observability = self
            .observability
            .map(|config| config.validate(config_directory))
            .transpose()?
            .unwrap_or_else(ObservabilityConfig::off);

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

        let grpc_route_specs = self
            .grpc_routes
            .into_iter()
            .map(|route| GrpcRouteSpec {
                id: route.id,
                path: route.path,
                backend: route.backend,
                enabled: route.enabled,
            })
            .collect();
        let grpc_routes = Arc::new(GrpcRouteTable::build(grpc_route_specs)?);

        Ok(Config {
            server: ServerConfig {
                listen: self.server.listen,
                tls_handshake_timeout,
                websocket_upgrade_timeout,
                backend_connect_timeout,
                shutdown_grace,
                max_websocket_message_size,
                max_grpc_concurrent_streams_per_backend,
            },
            tls: TlsConfig {
                cert: self.tls.cert,
                key: self.tls.key,
            },
            observability,
            routes,
            grpc_routes,
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
    #[serde(default = "default_max_grpc_concurrent_streams_per_backend")]
    max_grpc_concurrent_streams_per_backend: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTlsConfig {
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileObservabilityConfig {
    mode: FileObservabilityMode,
    summary_interval_seconds: u64,
    summary_file: PathBuf,
    diagnostic_interval_seconds: u64,
    diagnostic_file: PathBuf,
    connection_event_logs_enabled: bool,
}

impl FileObservabilityConfig {
    fn validate(self, config_directory: &Path) -> Result<ObservabilityConfig, ConfigError> {
        let summary_interval = validate_seconds(
            "observability.summary_interval_seconds",
            self.summary_interval_seconds,
            MAX_OBSERVABILITY_INTERVAL_SECONDS,
        )?;
        let diagnostic_interval = validate_seconds(
            "observability.diagnostic_interval_seconds",
            self.diagnostic_interval_seconds,
            MAX_OBSERVABILITY_INTERVAL_SECONDS,
        )?;
        validate_path("observability.summary_file", &self.summary_file)?;
        validate_path("observability.diagnostic_file", &self.diagnostic_file)?;

        Ok(ObservabilityConfig {
            mode: self.mode.into(),
            summary_interval,
            summary_file: resolve_config_path(config_directory, self.summary_file),
            diagnostic_interval,
            diagnostic_file: resolve_config_path(config_directory, self.diagnostic_file),
            connection_event_logs_enabled: self.connection_event_logs_enabled,
        })
    }
}

#[derive(Copy, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FileObservabilityMode {
    Off,
    Production,
    Diagnostic,
}

impl From<FileObservabilityMode> for ObservabilityMode {
    fn from(value: FileObservabilityMode) -> Self {
        match value {
            FileObservabilityMode::Off => Self::Off,
            FileObservabilityMode::Production => Self::Production,
            FileObservabilityMode::Diagnostic => Self::Diagnostic,
        }
    }
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGrpcRouteConfig {
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
    #[error("invalid WebSocket route configuration: {0}")]
    Route(#[from] RouteError),
    #[error("invalid gRPC route configuration: {0}")]
    GrpcRoute(#[from] GrpcRouteError),
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

fn validate_count(field: &'static str, value: usize, maximum: usize) -> Result<usize, ConfigError> {
    if value == 0 {
        return Err(ConfigError::Invalid(format!(
            "{field} must be greater than zero"
        )));
    }
    if value > maximum {
        return Err(ConfigError::Invalid(format!(
            "{field} must not exceed {maximum}"
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

fn resolve_config_path(config_directory: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        config_directory.join(path)
    }
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

const fn default_max_grpc_concurrent_streams_per_backend() -> usize {
    DEFAULT_MAX_GRPC_CONCURRENT_STREAMS_PER_BACKEND
}

const fn default_route_enabled() -> bool {
    true
}
