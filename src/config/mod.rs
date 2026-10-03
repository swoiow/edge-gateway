use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::grpc::{GrpcRouteError, GrpcRouteSpec, GrpcRouteTable};
use crate::http_proxy::config::{FileHttpProxyConfig, FileUpstreamConfig, UpstreamConfig};
use crate::http_proxy::routes::{FileHttpRouteConfig, HttpRouteTable};
use crate::routes::table::WebSocketHandshakeConfig;
use crate::routes::{RouteError, RouteSpec, RouteTable};
use crate::routing::{RoutingPolicy, normalize_dns_host};
use crate::security::{ClientAddressPolicy, CloudflareNetworks, IpNetwork, RouteSecurity};

const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_WEBSOCKET_UPGRADE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_BACKEND_CONNECT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_SHUTDOWN_GRACE_SECONDS: u64 = 30;
const DEFAULT_MAX_WEBSOCKET_MESSAGE_SIZE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_GRPC_CONCURRENT_STREAMS_PER_BACKEND: usize = 256;
const DEFAULT_ACME_FALLBACK_RENEW_BEFORE_DAYS: u64 = 30;
const DEFAULT_ACME_CHECK_INTERVAL_HOURS: u64 = 12;

const MAX_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 300;
const MAX_WEBSOCKET_UPGRADE_TIMEOUT_SECONDS: u64 = 300;
const MAX_BACKEND_CONNECT_TIMEOUT_SECONDS: u64 = 300;
const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 600;
const MAX_WEBSOCKET_MESSAGE_SIZE_BYTES: usize = 64 * 1024 * 1024;
const MAX_GRPC_CONCURRENT_STREAMS_PER_BACKEND: usize = 4096;
const MAX_OBSERVABILITY_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const MAX_ACME_FALLBACK_RENEW_BEFORE_DAYS: u64 = 90;
const MAX_ACME_CHECK_INTERVAL_HOURS: u64 = 7 * 24;

pub(crate) struct Config {
    server: ServerConfig,
    routing: Arc<RoutingPolicy>,
    client_address: Arc<ClientAddressPolicy>,
    tls: TlsConfig,
    acme: AcmeConfig,
    observability: ObservabilityConfig,
    fallback: Option<FallbackConfig>,
    routes: Arc<RouteTable>,
    grpc_routes: Arc<GrpcRouteTable>,
    http_routes: Arc<HttpRouteTable>,
    max_http_upstream_connections: usize,
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
        file_config.validate(config_directory).await
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ServerConfig,
        Arc<RoutingPolicy>,
        Arc<ClientAddressPolicy>,
        TlsConfig,
        AcmeConfig,
        ObservabilityConfig,
        Option<FallbackConfig>,
        Arc<RouteTable>,
        Arc<GrpcRouteTable>,
        Arc<HttpRouteTable>,
        usize,
    ) {
        (
            self.server,
            self.routing,
            self.client_address,
            self.tls,
            self.acme,
            self.observability,
            self.fallback,
            self.routes,
            self.grpc_routes,
            self.http_routes,
            self.max_http_upstream_connections,
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
    max_connections: usize,
    max_concurrent_tls_handshakes: usize,
    max_active_requests: usize,
    max_http_header_count: usize,
    max_http_header_bytes: usize,
    max_http2_concurrent_streams: usize,
    max_http2_send_buffer_bytes: usize,
    http_header_read_timeout: Duration,
}

impl ServerConfig {
    pub(crate) fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub(crate) fn max_concurrent_tls_handshakes(&self) -> usize {
        self.max_concurrent_tls_handshakes
    }

    pub(crate) fn max_active_requests(&self) -> usize {
        self.max_active_requests
    }

    pub(crate) fn max_http_header_count(&self) -> usize {
        self.max_http_header_count
    }

    pub(crate) fn max_http_header_bytes(&self) -> usize {
        self.max_http_header_bytes
    }

    pub(crate) fn max_http2_concurrent_streams(&self) -> usize {
        self.max_http2_concurrent_streams
    }

    pub(crate) fn max_http2_send_buffer_bytes(&self) -> usize {
        self.max_http2_send_buffer_bytes
    }

    pub(crate) fn http_header_read_timeout(&self) -> Duration {
        self.http_header_read_timeout
    }

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

#[derive(Clone)]
pub(crate) struct FallbackConfig {
    hosts: HashSet<String>,
    security: RouteSecurity,
    upstream: UpstreamConfig,
}
impl FallbackConfig {
    pub(crate) fn permits_host(&self, host: &str) -> bool {
        self.hosts.contains(host)
    }
    pub(crate) fn hosts(&self) -> impl Iterator<Item = &String> {
        self.hosts.iter()
    }
    pub(crate) fn security(&self) -> RouteSecurity {
        self.security
    }
    pub(crate) fn upstream(&self) -> &UpstreamConfig {
        &self.upstream
    }
}

#[derive(Clone)]
pub(crate) struct TlsConfig {
    cert_dir: PathBuf,
    cert_suffix: String,
    key_suffix: String,
    default_certificate: Option<String>,
}

impl TlsConfig {
    pub(crate) fn cert_dir(&self) -> &Path {
        &self.cert_dir
    }

    pub(crate) fn cert_suffix(&self) -> &str {
        &self.cert_suffix
    }

    pub(crate) fn key_suffix(&self) -> &str {
        &self.key_suffix
    }

    pub(crate) fn default_certificate(&self) -> Option<&str> {
        self.default_certificate.as_deref()
    }

    pub(crate) fn cert_path(&self, id: &str) -> PathBuf {
        self.cert_dir.join(format!("{id}{}", self.cert_suffix))
    }

    pub(crate) fn key_path(&self, id: &str) -> PathBuf {
        self.cert_dir.join(format!("{id}{}", self.key_suffix))
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum AcmeEnvironment {
    Production,
    Staging,
}

#[derive(Clone)]
pub(crate) struct AcmeCertificateConfig {
    id: String,
    domains: Vec<String>,
}

impl AcmeCertificateConfig {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn domains(&self) -> &[String] {
        &self.domains
    }
}

#[derive(Clone)]
pub(crate) struct AcmeConfig {
    enabled: bool,
    http01_listen: SocketAddr,
    email: Option<String>,
    environment: AcmeEnvironment,
    state_dir: PathBuf,
    fallback_renew_before: Duration,
    check_interval: Duration,
    certificates: Vec<AcmeCertificateConfig>,
}

impl AcmeConfig {
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn http01_listen(&self) -> SocketAddr {
        self.http01_listen
    }

    pub(crate) fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    pub(crate) fn environment(&self) -> AcmeEnvironment {
        self.environment
    }

    pub(crate) fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub(crate) fn fallback_renew_before(&self) -> Duration {
        self.fallback_renew_before
    }

    pub(crate) fn check_interval(&self) -> Duration {
        self.check_interval
    }

    pub(crate) fn certificates(&self) -> &[AcmeCertificateConfig] {
        &self.certificates
    }

    pub(crate) fn manages_certificate(&self, id: &str) -> bool {
        self.certificates.iter().any(|certificate| certificate.id() == id)
    }

    fn disabled(config_directory: &Path) -> Self {
        Self {
            enabled: false,
            http01_listen: default_acme_http01_listen(),
            email: None,
            environment: AcmeEnvironment::Production,
            state_dir: resolve_config_path(config_directory, PathBuf::from("state/acme")),
            fallback_renew_before: Duration::from_secs(
                DEFAULT_ACME_FALLBACK_RENEW_BEFORE_DAYS * 24 * 60 * 60,
            ),
            check_interval: Duration::from_secs(DEFAULT_ACME_CHECK_INTERVAL_HOURS * 60 * 60),
            certificates: Vec::new(),
        }
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
    detailed_frame_observation_enabled: bool,
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

    pub(crate) fn detailed_frame_observation_enabled(&self) -> bool {
        self.detailed_frame_observation_enabled
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
            detailed_frame_observation_enabled: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    security: FileSecurityConfig,
    #[serde(default)]
    http_proxy: FileHttpProxyConfig,
    #[serde(default)]
    routing: FileRoutingConfig,
    server: FileServerConfig,
    tls: FileTlsConfig,
    #[serde(default)]
    acme: Option<FileAcmeConfig>,
    #[serde(default)]
    observability: Option<FileObservabilityConfig>,
    #[serde(default)]
    fallback: Option<FileFallbackConfig>,
    #[serde(default)]
    routes: Vec<FileRouteConfig>,
    #[serde(default)]
    grpc_routes: Vec<FileGrpcRouteConfig>,
    #[serde(default)]
    http_routes: Vec<FileHttpRouteConfig>,
}

impl FileConfig {
    async fn validate(self, config_directory: &Path) -> Result<Config, ConfigError> {
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

        let needs_cloudflare =
            self.routes.iter().any(|route| route.enabled && route.security.cloudflare_only)
                || self
                    .grpc_routes
                    .iter()
                    .any(|route| route.enabled && route.security.cloudflare_only)
                || self
                    .http_routes
                    .iter()
                    .any(|route| route.enabled && route.security.cloudflare_only)
                || self
                    .fallback
                    .as_ref()
                    .is_some_and(|fallback| fallback.enabled && fallback.security.cloudflare_only);
        if self.routes.len() + self.grpc_routes.len() + self.http_routes.len() > 4096 {
            return Err(ConfigError::Invalid(
                "total configured routes must not exceed 4096".to_owned(),
            ));
        }
        let max_http_upstream_connections = validate_count(
            "http_proxy.max_connections",
            self.http_proxy.max_connections,
            1000000,
        )?;
        let max_connections = validate_count(
            "server.max_connections",
            self.server.max_connections,
            1000000,
        )?;
        let max_concurrent_tls_handshakes = validate_count(
            "server.max_concurrent_tls_handshakes",
            self.server.max_concurrent_tls_handshakes,
            65536,
        )?;
        let max_active_requests = validate_count(
            "server.max_active_requests",
            self.server.max_active_requests,
            1000000,
        )?;
        let max_http_header_count = validate_count(
            "server.max_http_header_count",
            self.server.max_http_header_count,
            1024,
        )?;
        let max_http_header_bytes = validate_count(
            "server.max_http_header_bytes",
            self.server.max_http_header_bytes,
            1048576,
        )?;
        let max_http2_concurrent_streams = validate_count(
            "server.max_http2_concurrent_streams",
            self.server.max_http2_concurrent_streams,
            65536,
        )?;
        let max_http2_send_buffer_bytes = validate_count(
            "server.max_http2_send_buffer_bytes",
            self.server.max_http2_send_buffer_bytes,
            1048576,
        )?;
        let http_header_read_timeout = validate_seconds(
            "server.http_header_read_timeout_seconds",
            self.server.http_header_read_timeout_seconds,
            300,
        )?;
        if max_http_header_bytes < 8192 {
            return Err(ConfigError::Invalid(
                "server.max_http_header_bytes must be at least 8192".to_owned(),
            ));
        }
        if max_concurrent_tls_handshakes > max_connections {
            return Err(ConfigError::Invalid(
                "TLS handshake capacity must not exceed max_connections".to_owned(),
            ));
        }

        let tls = self.tls.validate(config_directory)?;
        let acme = self
            .acme
            .map(|config| config.validate(config_directory))
            .transpose()?
            .unwrap_or_else(|| AcmeConfig::disabled(config_directory));

        let observability = self
            .observability
            .map(|config| config.validate(config_directory))
            .transpose()?
            .unwrap_or_else(ObservabilityConfig::off);

        let fallback = self
            .fallback
            .map(|config| config.validate(config_directory))
            .transpose()?
            .flatten();

        let route_specs: Vec<RouteSpec> = self
            .routes
            .into_iter()
            .map(|route| RouteSpec {
                id: route.id,
                host: route.host,
                path: route.path,
                backend: route.backend,
                enabled: route.enabled,
                security: route.security,
                handshake: route.handshake,
            })
            .collect();
        let mut hosts = HashSet::new();
        let mut websocket_paths = HashSet::new();
        for route in &route_specs {
            if matches!(route.path.as_str(), "/health/live" | "/health/ready") {
                return Err(ConfigError::Invalid(
                    "WebSocket routes must not use reserved health paths".to_owned(),
                ));
            }
            crate::http_proxy::routes::validate_http_path(&route.path)
                .map_err(|reason| ConfigError::Invalid(format!("routes.path: {reason}")))?;
            let host = normalize_dns_host(&route.host)
                .map_err(|reason| ConfigError::Invalid(format!("routes.host: {reason}")))?;
            websocket_paths.insert((host.clone(), route.path.clone()));
            if route.enabled {
                hosts.insert(host);
            }
        }
        let routes = Arc::new(RouteTable::build(route_specs)?);

        let grpc_route_specs: Vec<GrpcRouteSpec> = self
            .grpc_routes
            .into_iter()
            .map(|route| GrpcRouteSpec {
                id: route.id,
                host: route.host,
                path: route.path,
                backend: route.backend,
                enabled: route.enabled,
                security: route.security,
            })
            .collect();
        for route in &grpc_route_specs {
            let host = normalize_dns_host(&route.host)
                .map_err(|reason| ConfigError::Invalid(format!("grpc_routes.host: {reason}")))?;
            if websocket_paths.contains(&(host.clone(), route.path.clone())) {
                return Err(ConfigError::Invalid(format!(
                    "WS and gRPC conflict at {host}{}",
                    route.path
                )));
            }
            websocket_paths.insert((host.clone(), route.path.clone()));
            if route.enabled {
                hosts.insert(host);
            }
        }
        let grpc_routes = Arc::new(GrpcRouteTable::build(grpc_route_specs)?);
        let http_routes = Arc::new(
            HttpRouteTable::build(self.http_routes, config_directory, &websocket_paths)
                .map_err(ConfigError::Invalid)?,
        );
        hosts.extend(http_routes.hosts().cloned());
        if let Some(fallback) = &fallback {
            hosts.extend(fallback.hosts().cloned());
        }
        let bindings = self.routing.sni_bindings.into_iter().map(|b| (b.sni, b.hosts)).collect();
        let routing = Arc::new(
            RoutingPolicy::build(hosts, self.routing.require_sni, bindings)
                .map_err(ConfigError::Invalid)?,
        );
        let client_address =
            Arc::new(self.security.validate(config_directory, needs_cloudflare).await?);

        Ok(Config {
            server: ServerConfig {
                listen: self.server.listen,
                tls_handshake_timeout,
                websocket_upgrade_timeout,
                backend_connect_timeout,
                shutdown_grace,
                max_websocket_message_size,
                max_grpc_concurrent_streams_per_backend,
                max_connections,
                max_concurrent_tls_handshakes,
                max_active_requests,
                max_http_header_count,
                max_http_header_bytes,
                max_http2_concurrent_streams,
                max_http2_send_buffer_bytes,
                http_header_read_timeout,
            },
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
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_max_concurrent_tls_handshakes")]
    max_concurrent_tls_handshakes: usize,
    #[serde(default = "default_max_active_requests")]
    max_active_requests: usize,
    #[serde(default = "default_max_http_header_count")]
    max_http_header_count: usize,
    #[serde(default = "default_max_http_header_bytes")]
    max_http_header_bytes: usize,
    #[serde(default = "default_max_http2_concurrent_streams")]
    max_http2_concurrent_streams: usize,
    #[serde(default = "default_max_http2_send_buffer_bytes")]
    max_http2_send_buffer_bytes: usize,
    #[serde(default = "default_http_header_read_timeout_seconds")]
    http_header_read_timeout_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTlsConfig {
    cert_dir: PathBuf,
    #[serde(default = "default_tls_cert_suffix")]
    cert_suffix: String,
    #[serde(default = "default_tls_key_suffix")]
    key_suffix: String,
    #[serde(default)]
    default_certificate: Option<String>,
}

impl FileTlsConfig {
    fn validate(self, config_directory: &Path) -> Result<TlsConfig, ConfigError> {
        validate_path("tls.cert_dir", &self.cert_dir)?;
        validate_suffix("tls.cert_suffix", &self.cert_suffix)?;
        validate_suffix("tls.key_suffix", &self.key_suffix)?;
        if self.cert_suffix == self.key_suffix
            || self.cert_suffix.ends_with(&self.key_suffix)
            || self.key_suffix.ends_with(&self.cert_suffix)
        {
            return Err(ConfigError::Invalid(
                "tls.cert_suffix and tls.key_suffix must be distinct and non-overlapping"
                    .to_owned(),
            ));
        }
        if let Some(id) = self.default_certificate.as_deref() {
            validate_certificate_id("tls.default_certificate", id)?;
        }

        Ok(TlsConfig {
            cert_dir: resolve_config_path(config_directory, self.cert_dir),
            cert_suffix: self.cert_suffix,
            key_suffix: self.key_suffix,
            default_certificate: self.default_certificate,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileAcmeConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_acme_http01_listen")]
    http01_listen: SocketAddr,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    environment: FileAcmeEnvironment,
    #[serde(default = "default_acme_state_dir")]
    state_dir: PathBuf,
    #[serde(default = "default_acme_fallback_renew_before_days")]
    fallback_renew_before_days: u64,
    #[serde(default = "default_acme_check_interval_hours")]
    check_interval_hours: u64,
    #[serde(default)]
    certificates: Vec<FileAcmeCertificateConfig>,
}

impl FileAcmeConfig {
    fn validate(self, config_directory: &Path) -> Result<AcmeConfig, ConfigError> {
        validate_path("acme.state_dir", &self.state_dir)?;

        if self.fallback_renew_before_days == 0
            || self.fallback_renew_before_days > MAX_ACME_FALLBACK_RENEW_BEFORE_DAYS
        {
            return Err(ConfigError::Invalid(format!(
                "acme.fallback_renew_before_days must be between 1 and {MAX_ACME_FALLBACK_RENEW_BEFORE_DAYS}"
            )));
        }
        if self.check_interval_hours == 0
            || self.check_interval_hours > MAX_ACME_CHECK_INTERVAL_HOURS
        {
            return Err(ConfigError::Invalid(format!(
                "acme.check_interval_hours must be between 1 and {MAX_ACME_CHECK_INTERVAL_HOURS}"
            )));
        }

        let email = self
            .email
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if self.enabled && email.is_none() {
            return Err(ConfigError::Invalid(
                "acme.email is required when ACME is enabled".to_owned(),
            ));
        }
        if let Some(value) = email.as_deref()
            && (value.contains(char::is_whitespace) || !value.contains('@'))
        {
            return Err(ConfigError::Invalid(
                "acme.email must be a plain email address".to_owned(),
            ));
        }
        if self.enabled && self.certificates.is_empty() {
            return Err(ConfigError::Invalid(
                "acme.certificates must contain at least one managed certificate when ACME is enabled"
                    .to_owned(),
            ));
        }

        let mut certificate_ids = HashSet::new();
        let mut managed_domains = HashSet::new();
        let mut certificates = Vec::with_capacity(self.certificates.len());
        for (index, certificate) in self.certificates.into_iter().enumerate() {
            let id_field = format!("acme.certificates[{index}].id");
            validate_certificate_id(&id_field, &certificate.id)?;
            if !certificate_ids.insert(certificate.id.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate ACME certificate id {:?}",
                    certificate.id
                )));
            }
            if certificate.domains.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "acme.certificates[{index}].domains must not be empty"
                )));
            }

            let mut local_domains = HashSet::new();
            let mut domains = Vec::with_capacity(certificate.domains.len());
            for domain in certificate.domains {
                let domain = normalize_domain(&domain).map_err(|reason| {
                    ConfigError::Invalid(format!(
                        "invalid acme.certificates[{index}] domain {domain:?}: {reason}"
                    ))
                })?;
                if !local_domains.insert(domain.clone()) {
                    return Err(ConfigError::Invalid(format!(
                        "duplicate domain {domain:?} in ACME certificate {:?}",
                        certificate.id
                    )));
                }
                if !managed_domains.insert(domain.clone()) {
                    return Err(ConfigError::Invalid(format!(
                        "ACME domain {domain:?} is assigned to more than one certificate"
                    )));
                }
                domains.push(domain);
            }
            domains.sort();
            certificates.push(AcmeCertificateConfig {
                id: certificate.id,
                domains,
            });
        }

        Ok(AcmeConfig {
            enabled: self.enabled,
            http01_listen: self.http01_listen,
            email,
            environment: self.environment.into(),
            state_dir: resolve_config_path(config_directory, self.state_dir),
            fallback_renew_before: Duration::from_secs(
                self.fallback_renew_before_days * 24 * 60 * 60,
            ),
            check_interval: Duration::from_secs(self.check_interval_hours * 60 * 60),
            certificates,
        })
    }
}

#[derive(Copy, Clone, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FileAcmeEnvironment {
    #[default]
    Production,
    Staging,
}

impl From<FileAcmeEnvironment> for AcmeEnvironment {
    fn from(value: FileAcmeEnvironment) -> Self {
        match value {
            FileAcmeEnvironment::Production => Self::Production,
            FileAcmeEnvironment::Staging => Self::Staging,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileAcmeCertificateConfig {
    id: String,
    domains: Vec<String>,
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
    #[serde(default)]
    detailed_frame_observation_enabled: bool,
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
            detailed_frame_observation_enabled: self.detailed_frame_observation_enabled,
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
struct FileFallbackConfig {
    hosts: Vec<String>,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    security: RouteSecurity,
    upstream: FileUpstreamConfig,
}
impl FileFallbackConfig {
    fn validate(self, directory: &Path) -> Result<Option<FallbackConfig>, ConfigError> {
        if self.hosts.is_empty() || self.hosts.len() > 1024 {
            return Err(ConfigError::Invalid(
                "fallback.hosts must contain 1..1024 names".to_owned(),
            ));
        }
        let mut hosts = HashSet::new();
        for host in self.hosts {
            let host = normalize_dns_host(&host)
                .map_err(|reason| ConfigError::Invalid(format!("fallback.hosts: {reason}")))?;
            if !hosts.insert(host.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate fallback host {host}"
                )));
            }
        }
        let upstream = self
            .upstream
            .validate(directory)
            .map_err(|reason| ConfigError::Invalid(format!("fallback: {reason}")))?;
        Ok(self.enabled.then_some(FallbackConfig {
            hosts,
            security: self.security,
            upstream,
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRouteConfig {
    #[serde(default)]
    security: RouteSecurity,
    #[serde(default)]
    handshake: WebSocketHandshakeConfig,
    id: String,
    host: String,
    path: String,
    backend: String,
    #[serde(default = "default_route_enabled")]
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGrpcRouteConfig {
    #[serde(default)]
    security: RouteSecurity,
    id: String,
    host: String,
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

fn validate_path(field: &str, path: &Path) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::Invalid(format!("{field} must not be empty")));
    }

    Ok(())
}

fn validate_suffix(field: &str, suffix: &str) -> Result<(), ConfigError> {
    if suffix.is_empty() {
        return Err(ConfigError::Invalid(format!("{field} must not be empty")));
    }
    if suffix.contains('/') || suffix.contains('\\') {
        return Err(ConfigError::Invalid(format!(
            "{field} must be a filename suffix, not a path"
        )));
    }
    Ok(())
}

fn validate_certificate_id(field: &str, id: &str) -> Result<(), ConfigError> {
    if id.is_empty() {
        return Err(ConfigError::Invalid(format!("{field} must not be empty")));
    }
    if !id
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(ConfigError::Invalid(format!(
            "{field} may contain only ASCII letters, digits, '.', '-' and '_'"
        )));
    }
    Ok(())
}

fn normalize_domain(domain: &str) -> Result<String, &'static str> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err("domain must not be empty");
    }
    if domain.starts_with("*.") {
        return Err("wildcard domains require DNS-01 and are not supported by built-in HTTP-01");
    }
    if domain.len() > 253 || !domain.is_ascii() {
        return Err("domain must be an ASCII DNS name no longer than 253 characters");
    }
    if domain.parse::<IpAddr>().is_ok() {
        return Err("IP identifiers are not supported by built-in ACME");
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("DNS labels must contain between 1 and 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("DNS labels must not start or end with '-'");
        }
        if !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err("DNS labels may contain only ASCII letters, digits and '-'");
        }
    }
    Ok(domain)
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

fn default_tls_cert_suffix() -> String {
    ".fullchain.pem".to_owned()
}

fn default_tls_key_suffix() -> String {
    ".key.pem".to_owned()
}

fn default_acme_http01_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 80))
}

fn default_acme_state_dir() -> PathBuf {
    PathBuf::from("state/acme")
}

const fn default_acme_fallback_renew_before_days() -> u64 {
    DEFAULT_ACME_FALLBACK_RENEW_BEFORE_DAYS
}

const fn default_acme_check_interval_hours() -> u64 {
    DEFAULT_ACME_CHECK_INTERVAL_HOURS
}

const fn default_route_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        FileFallbackConfig, FileTlsConfig, FileUpstreamConfig, RouteSecurity, normalize_domain,
    };
    use crate::http_proxy::config::{HostHeaderPolicy, TlsServerName};

    #[test]
    fn acme_domain_normalization_rejects_wildcards() {
        assert!(normalize_domain("*.example.com").is_err());
        assert!(normalize_domain("192.0.2.10").is_err());
        assert_eq!(
            normalize_domain("API.Example.COM."),
            Ok("api.example.com".to_owned())
        );
    }

    #[test]
    fn fallback_https_loopback_preserves_request_host_by_default() {
        let result = FileFallbackConfig {
            enabled: true,
            hosts: vec!["api.example.com".to_owned()],
            security: RouteSecurity::default(),
            upstream: FileUpstreamConfig {
                endpoint: "https://127.0.0.1:9443".to_owned(),
                protocol: Default::default(),
                host_header: HostHeaderPolicy::Preserve,
                tls_server_name: "request_host".to_owned(),
                ca_file: None,
                pool: Default::default(),
            },
        }
        .validate(Path::new("."));

        assert!(matches!(&result, Ok(Some(_))));
        if let Ok(Some(config)) = result {
            assert!(config.upstream().tls);
            assert!(config.upstream().host_header == HostHeaderPolicy::Preserve);
            assert_eq!(
                &config.upstream().tls_server_name,
                &TlsServerName::RequestHost
            );
        }
    }

    #[test]
    fn fallback_requires_loopback_backend() {
        let result = FileFallbackConfig {
            enabled: true,
            hosts: vec!["api.example.com".to_owned()],
            security: RouteSecurity::default(),
            upstream: FileUpstreamConfig {
                endpoint: "https://192.0.2.10:9443".to_owned(),
                protocol: Default::default(),
                host_header: HostHeaderPolicy::Preserve,
                tls_server_name: "request_host".to_owned(),
                ca_file: None,
                pool: Default::default(),
            },
        }
        .validate(Path::new("."));
        assert!(result.is_err());
    }

    #[test]
    fn tls_suffixes_must_not_overlap() {
        let result = FileTlsConfig {
            cert_dir: PathBuf::from("certs"),
            cert_suffix: ".pem".to_owned(),
            key_suffix: ".key.pem".to_owned(),
            default_certificate: None,
        }
        .validate(Path::new("."));
        assert!(result.is_err());
    }
}

const fn default_max_connections() -> usize {
    20000
}

const fn default_max_concurrent_tls_handshakes() -> usize {
    512
}

const fn default_max_active_requests() -> usize {
    20000
}

const fn default_max_http_header_count() -> usize {
    100
}

const fn default_max_http_header_bytes() -> usize {
    32768
}

const fn default_max_http2_concurrent_streams() -> usize {
    256
}

const fn default_max_http2_send_buffer_bytes() -> usize {
    65536
}

const fn default_http_header_read_timeout_seconds() -> u64 {
    10
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRoutingConfig {
    #[serde(default = "default_require_sni")]
    require_sni: bool,
    #[serde(default)]
    sni_bindings: Vec<FileSniBinding>,
}
impl Default for FileRoutingConfig {
    fn default() -> Self {
        Self {
            require_sni: true,
            sni_bindings: Vec::new(),
        }
    }
}
const fn default_require_sni() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSniBinding {
    sni: String,
    hosts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileSecurityConfig {
    #[serde(default = "default_health_peer_cidrs")]
    health_peer_cidrs: Vec<String>,
    cloudflare: Option<FileCloudflareConfig>,
    ip_blocking: crate::security::FileIpBlockingConfig,
}
impl Default for FileSecurityConfig {
    fn default() -> Self {
        Self {
            health_peer_cidrs: default_health_peer_cidrs(),
            cloudflare: None,
            ip_blocking: crate::security::FileIpBlockingConfig::default(),
        }
    }
}
fn default_health_peer_cidrs() -> Vec<String> {
    vec!["127.0.0.0/8".to_owned(), "::1/128".to_owned()]
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileCloudflareConfig {
    cache_file: PathBuf,
}
impl Default for FileCloudflareConfig {
    fn default() -> Self {
        Self {
            cache_file: PathBuf::from("state/cloudflare-cidrs.txt"),
        }
    }
}
impl FileSecurityConfig {
    async fn validate(
        self,
        directory: &Path,
        needs_cloudflare: bool,
    ) -> Result<ClientAddressPolicy, ConfigError> {
        if self.health_peer_cidrs.len() > 128 {
            return Err(ConfigError::Invalid(
                "security.health_peer_cidrs exceeds 128 entries".to_owned(),
            ));
        }
        let health = self
            .health_peer_cidrs
            .iter()
            .map(|value| {
                IpNetwork::parse(value).map_err(|reason| {
                    ConfigError::Invalid(format!("security.health_peer_cidrs {value:?}: {reason}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cache_file = if needs_cloudflare || self.cloudflare.is_some() {
            let config = self.cloudflare.unwrap_or_default();
            validate_path("security.cloudflare.cache_file", &config.cache_file)?;
            Some(resolve_config_path(directory, config.cache_file))
        } else {
            None
        };
        let block_config = self
            .ip_blocking
            .validate(directory)
            .map_err(|error| ConfigError::Invalid(format!("security.ip_blocking: {error:#}")))?;
        let ip_blocking = crate::security::IpBlockingRuntime::load(block_config)
            .await
            .map_err(|error| ConfigError::Invalid(format!("security.ip_blocking: {error:#}")))?;
        let networks = CloudflareNetworks::load(cache_file)
            .await
            .map_err(|error| ConfigError::Invalid(format!("security.cloudflare: {error:#}")))?;
        Ok(ClientAddressPolicy::new(networks, health, ip_blocking))
    }
}
