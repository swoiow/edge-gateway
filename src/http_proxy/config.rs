use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper::Uri;
use serde::Deserialize;

use crate::routing::normalize_dns_host;

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpstreamProtocol {
    #[default]
    Http1,
    Http2,
}

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostHeaderPolicy {
    #[default]
    Preserve,
    Backend,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TlsServerName {
    RequestHost,
    Literal(String),
}

#[derive(Clone)]
pub(crate) struct UpstreamConfig {
    pub(crate) endpoint: String,
    pub(crate) address: SocketAddr,
    pub(crate) authority: String,
    pub(crate) tls: bool,
    pub(crate) protocol: UpstreamProtocol,
    pub(crate) host_header: HostHeaderPolicy,
    pub(crate) tls_server_name: TlsServerName,
    pub(crate) ca_file: Option<PathBuf>,
    pub(crate) pool: PoolConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileUpstreamConfig {
    pub(crate) endpoint: String,
    #[serde(default)]
    pub(crate) protocol: UpstreamProtocol,
    #[serde(default)]
    pub(crate) host_header: HostHeaderPolicy,
    #[serde(default = "default_tls_server_name")]
    pub(crate) tls_server_name: String,
    #[serde(default)]
    pub(crate) ca_file: Option<PathBuf>,
    #[serde(default)]
    pub(crate) pool: FilePoolConfig,
}

impl FileUpstreamConfig {
    pub(crate) fn validate(self, directory: &Path) -> Result<UpstreamConfig, String> {
        if self.endpoint.contains('#') {
            return Err("upstream.endpoint must not contain a fragment".to_owned());
        }
        let uri = self
            .endpoint
            .parse::<Uri>()
            .map_err(|error| format!("invalid upstream.endpoint: {error}"))?;
        let tls = match uri.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            _ => return Err("upstream.endpoint scheme must be http or https".to_owned()),
        };
        let authority = uri.authority().ok_or("upstream.endpoint requires an authority")?;
        if authority.as_str().contains('@') {
            return Err("upstream.endpoint must not contain userinfo".to_owned());
        }
        let host = uri.host().ok_or("upstream.endpoint requires a host")?;
        let ip = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map_err(|_| "upstream.endpoint host must be a literal loopback address")?;
        if !ip.is_loopback() {
            return Err(
                "upstream.endpoint host must be loopback; publish Docker ports locally".to_owned(),
            );
        }
        let port = uri
            .port_u16()
            .filter(|port| *port != 0)
            .ok_or("upstream.endpoint requires an explicit nonzero port")?;
        if uri.path_and_query().map(|value| value.as_str()).unwrap_or("/") != "/" {
            return Err(
                "upstream.endpoint is an origin only; configure paths with route rewrite"
                    .to_owned(),
            );
        }
        let tls_server_name = if self.tls_server_name == "request_host" {
            TlsServerName::RequestHost
        } else {
            TlsServerName::Literal(
                normalize_dns_host(&self.tls_server_name).map_err(str::to_owned)?,
            )
        };
        if !tls && self.ca_file.is_some() {
            return Err("upstream.ca_file requires https".to_owned());
        }
        if self.ca_file.as_ref().is_some_and(|path| path.as_os_str().is_empty()) {
            return Err("upstream.ca_file must not be empty".to_owned());
        }
        let ca_file = self.ca_file.map(|path| {
            if path.is_absolute() {
                path
            } else {
                directory.join(path)
            }
        });
        Ok(UpstreamConfig {
            endpoint: self.endpoint,
            address: SocketAddr::new(ip, port),
            authority: authority.as_str().to_owned(),
            tls,
            protocol: self.protocol,
            host_header: self.host_header,
            tls_server_name,
            ca_file,
            pool: self.pool.validate()?,
        })
    }
}
fn default_tls_server_name() -> String {
    "request_host".to_owned()
}

#[derive(Clone)]
pub(crate) struct PoolConfig {
    pub(crate) max_connections: usize,
    pub(crate) max_idle_connections: usize,
    pub(crate) max_active_requests: usize,
    pub(crate) max_pending_requests: usize,
    pub(crate) idle_timeout: Duration,
    pub(crate) pending_timeout: Duration,
    pub(crate) response_header_timeout: Duration,
    pub(crate) body_idle_timeout: Duration,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FilePoolConfig {
    pub(crate) max_connections: usize,
    pub(crate) max_idle_connections: usize,
    pub(crate) max_active_requests: usize,
    pub(crate) max_pending_requests: usize,
    pub(crate) idle_timeout_seconds: u64,
    pub(crate) pending_timeout_seconds: u64,
    pub(crate) response_header_timeout_seconds: u64,
    pub(crate) body_idle_timeout_seconds: u64,
}
impl Default for FilePoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 128,
            max_idle_connections: 16,
            max_active_requests: 256,
            max_pending_requests: 64,
            idle_timeout_seconds: 60,
            pending_timeout_seconds: 5,
            response_header_timeout_seconds: 60,
            body_idle_timeout_seconds: 60,
        }
    }
}
impl FilePoolConfig {
    fn validate(self) -> Result<PoolConfig, String> {
        for (name, value, max) in [
            ("max_connections", self.max_connections, 65536),
            ("max_active_requests", self.max_active_requests, 65536),
        ] {
            if value == 0 || value > max {
                return Err(format!("upstream.pool.{name} must be between 1 and {max}"));
            }
        }
        if self.max_idle_connections > self.max_connections
            || self.max_pending_requests > self.max_active_requests
        {
            return Err("pool idle capacity must not exceed connections; pending capacity must not exceed active requests".to_owned());
        }
        for (name, seconds) in [
            ("idle_timeout_seconds", self.idle_timeout_seconds),
            ("pending_timeout_seconds", self.pending_timeout_seconds),
            (
                "response_header_timeout_seconds",
                self.response_header_timeout_seconds,
            ),
            ("body_idle_timeout_seconds", self.body_idle_timeout_seconds),
        ] {
            if seconds == 0 || seconds > 3600 {
                return Err(format!("upstream.pool.{name} must be between 1 and 3600"));
            }
        }
        Ok(PoolConfig {
            max_connections: self.max_connections,
            max_idle_connections: self.max_idle_connections,
            max_active_requests: self.max_active_requests,
            max_pending_requests: self.max_pending_requests,
            idle_timeout: Duration::from_secs(self.idle_timeout_seconds),
            pending_timeout: Duration::from_secs(self.pending_timeout_seconds),
            response_header_timeout: Duration::from_secs(self.response_header_timeout_seconds),
            body_idle_timeout: Duration::from_secs(self.body_idle_timeout_seconds),
        })
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FileHttpProxyConfig {
    pub(crate) max_connections: usize,
}
impl Default for FileHttpProxyConfig {
    fn default() -> Self {
        Self {
            max_connections: 20000,
        }
    }
}
