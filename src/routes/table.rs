use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hyper::Uri;
use hyper::header::HeaderValue;
use thiserror::Error;
use tracing::warn;

const MAX_ROUTE_ID_LENGTH: usize = 128;
const MAX_ROUTE_PATH_LENGTH: usize = 2048;
const PC_ROUTE_PREFIX: &str = "/api/pc/";
const MOBILE_ROUTE_PREFIX: &str = "/api/mob/";
const UAT_ROUTE_PREFIX: &str = "/api/uat/";

pub(crate) struct RouteSpec {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) backend: String,
    pub(crate) enabled: bool,
}

pub(crate) struct RouteTable {
    enabled_by_path: HashMap<Arc<str>, Arc<Route>>,
    configured_count: usize,
}

impl RouteTable {
    pub(crate) fn build(specs: Vec<RouteSpec>) -> Result<Self, RouteError> {
        let configured_count = specs.len();
        let mut ids = HashSet::with_capacity(configured_count);
        let mut paths = HashSet::with_capacity(configured_count);
        let mut enabled_by_path = HashMap::with_capacity(configured_count);

        for spec in specs {
            validate_id(&spec.id)?;
            let namespace = validate_public_path(&spec.path)?;
            if namespace == RouteNamespace::Custom {
                warn!(
                    route_id = %spec.id,
                    path = %spec.path,
                    "WebSocket route uses a custom path outside /api/pc/, /api/mob/, and /api/uat/"
                );
            }

            if !ids.insert(spec.id.clone()) {
                return Err(RouteError::DuplicateId(spec.id));
            }
            if !paths.insert(spec.path.clone()) {
                return Err(RouteError::DuplicatePath(spec.path));
            }

            let backend = BackendEndpoint::parse(&spec.backend)?;
            if spec.enabled {
                let route = Arc::new(Route {
                    id: Arc::from(spec.id),
                    path: Arc::from(spec.path),
                    namespace,
                    backend,
                });
                enabled_by_path.insert(Arc::clone(&route.path), route);
            }
        }

        Ok(Self {
            enabled_by_path,
            configured_count,
        })
    }

    pub(crate) fn resolve(&self, path: &str) -> Option<Arc<Route>> {
        self.enabled_by_path.get(path).cloned()
    }

    pub(crate) fn configured_count(&self) -> usize {
        self.configured_count
    }

    pub(crate) fn enabled_count(&self) -> usize {
        self.enabled_by_path.len()
    }
}

pub(crate) struct Route {
    id: Arc<str>,
    path: Arc<str>,
    namespace: RouteNamespace,
    backend: BackendEndpoint,
}

impl Route {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) const fn namespace(&self) -> RouteNamespace {
        self.namespace
    }

    pub(crate) fn backend(&self) -> &BackendEndpoint {
        &self.backend
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteNamespace {
    Pc,
    Mobile,
    Uat,
    Custom,
}

impl RouteNamespace {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pc => "pc",
            Self::Mobile => "mob",
            Self::Uat => "uat",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackendKind {
    WebSocket,
    Tcp,
}

pub(crate) enum BackendEndpoint {
    WebSocket(WebSocketBackendEndpoint),
    Tcp(TcpBackendEndpoint),
}

impl BackendEndpoint {
    fn parse(value: &str) -> Result<Self, RouteError> {
        let uri = value.parse::<Uri>().map_err(|source| RouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: source.to_string(),
        })?;

        match uri.scheme_str() {
            Some("ws") => WebSocketBackendEndpoint::from_uri(value, &uri).map(Self::WebSocket),
            Some("tcp") => TcpBackendEndpoint::from_uri(value, &uri).map(Self::Tcp),
            Some(scheme) => Err(RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: format!("unsupported scheme {scheme:?}; expected ws or tcp"),
            }),
            None => Err(RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: "scheme is required; expected ws or tcp".to_owned(),
            }),
        }
    }

    pub(crate) const fn kind(&self) -> BackendKind {
        match self {
            Self::WebSocket(_) => BackendKind::WebSocket,
            Self::Tcp(_) => BackendKind::Tcp,
        }
    }

    pub(crate) fn display(&self) -> &str {
        match self {
            Self::WebSocket(endpoint) => endpoint.display(),
            Self::Tcp(endpoint) => endpoint.display(),
        }
    }

    pub(crate) const fn address(&self) -> SocketAddr {
        match self {
            Self::WebSocket(endpoint) => endpoint.address(),
            Self::Tcp(endpoint) => endpoint.address(),
        }
    }

    pub(crate) fn websocket(&self) -> Option<&WebSocketBackendEndpoint> {
        match self {
            Self::WebSocket(endpoint) => Some(endpoint),
            Self::Tcp(_) => None,
        }
    }
}

pub(crate) struct WebSocketBackendEndpoint {
    display: Arc<str>,
    address: SocketAddr,
    request_target: Uri,
    host_header: HeaderValue,
}

impl WebSocketBackendEndpoint {
    fn from_uri(value: &str, uri: &Uri) -> Result<Self, RouteError> {
        let (address, authority) = parse_loopback_authority(value, uri, Some(80), false)?;
        let request_target = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .parse::<Uri>()
            .map_err(|source| RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: format!("invalid request target: {source}"),
            })?;
        let host_header =
            HeaderValue::from_str(authority).map_err(|source| RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: format!("invalid authority: {source}"),
            })?;

        Ok(Self {
            display: Arc::from(value),
            address,
            request_target,
            host_header,
        })
    }

    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn request_target(&self) -> &Uri {
        &self.request_target
    }

    pub(crate) fn host_header(&self) -> &HeaderValue {
        &self.host_header
    }
}

pub(crate) struct TcpBackendEndpoint {
    display: Arc<str>,
    address: SocketAddr,
}

impl TcpBackendEndpoint {
    fn from_uri(value: &str, uri: &Uri) -> Result<Self, RouteError> {
        let (address, _authority) = parse_loopback_authority(value, uri, None, true)?;
        let request_target = uri.path_and_query().map(|value| value.as_str()).unwrap_or("/");
        if request_target != "/" {
            return Err(RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: "tcp backend URL must not contain a path or query".to_owned(),
            });
        }

        Ok(Self {
            display: Arc::from(value),
            address,
        })
    }

    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }
}

fn parse_loopback_authority<'a>(
    value: &str,
    uri: &'a Uri,
    default_port: Option<u16>,
    require_explicit_port: bool,
) -> Result<(SocketAddr, &'a str), RouteError> {
    let authority = uri.authority().ok_or_else(|| RouteError::InvalidBackend {
        backend: value.to_owned(),
        reason: "authority is required".to_owned(),
    })?;

    if authority.as_str().contains('@') {
        return Err(RouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: "userinfo is not allowed".to_owned(),
        });
    }

    let host = uri.host().ok_or_else(|| RouteError::InvalidBackend {
        backend: value.to_owned(),
        reason: "host is required".to_owned(),
    })?;
    let ip = host.parse::<IpAddr>().map_err(|_| RouteError::InvalidBackend {
        backend: value.to_owned(),
        reason: "host must be an IPv4 or IPv6 loopback address".to_owned(),
    })?;
    if !ip.is_loopback() {
        return Err(RouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: "host must be a loopback address".to_owned(),
        });
    }

    let port = match uri.port_u16() {
        Some(port) => port,
        None if require_explicit_port => {
            return Err(RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: "an explicit port is required".to_owned(),
            });
        }
        None => default_port.ok_or_else(|| RouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: "an explicit port is required".to_owned(),
        })?,
    };

    Ok((SocketAddr::new(ip, port), authority.as_str()))
}

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("route id must not be empty")]
    EmptyId,
    #[error("route id {0:?} exceeds {MAX_ROUTE_ID_LENGTH} bytes")]
    IdTooLong(String),
    #[error("route id {0:?} contains control or whitespace characters")]
    InvalidId(String),
    #[error(
        "route path {0:?} must be an exact absolute path without empty/dot segments, query, fragment, backslash, whitespace, or control characters"
    )]
    InvalidPath(String),
    #[error("route path {0:?} exceeds {MAX_ROUTE_PATH_LENGTH} bytes")]
    PathTooLong(String),
    #[error("duplicate route id {0:?}")]
    DuplicateId(String),
    #[error("duplicate route path {0:?}")]
    DuplicatePath(String),
    #[error("invalid backend {backend:?}: {reason}")]
    InvalidBackend { backend: String, reason: String },
}

fn validate_id(id: &str) -> Result<(), RouteError> {
    if id.is_empty() {
        return Err(RouteError::EmptyId);
    }
    if id.len() > MAX_ROUTE_ID_LENGTH {
        return Err(RouteError::IdTooLong(id.to_owned()));
    }
    if id.chars().any(char::is_whitespace) || id.chars().any(char::is_control) {
        return Err(RouteError::InvalidId(id.to_owned()));
    }

    Ok(())
}

fn validate_public_path(path: &str) -> Result<RouteNamespace, RouteError> {
    if path.len() > MAX_ROUTE_PATH_LENGTH {
        return Err(RouteError::PathTooLong(path.to_owned()));
    }
    if !path.starts_with('/')
        || path.contains(['?', '#', '\\'])
        || path.chars().any(char::is_whitespace)
        || path.chars().any(char::is_control)
    {
        return Err(RouteError::InvalidPath(path.to_owned()));
    }

    if path != "/"
        && path[1..]
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(RouteError::InvalidPath(path.to_owned()));
    }

    let namespace = if path.starts_with(PC_ROUTE_PREFIX) {
        RouteNamespace::Pc
    } else if path.starts_with(MOBILE_ROUTE_PREFIX) {
        RouteNamespace::Mobile
    } else if path.starts_with(UAT_ROUTE_PREFIX) {
        RouteNamespace::Uat
    } else {
        RouteNamespace::Custom
    };

    Ok(namespace)
}

#[cfg(test)]
mod tests {
    use super::{BackendEndpoint, BackendKind, RouteNamespace, validate_public_path};

    #[test]
    fn custom_absolute_paths_are_allowed() {
        assert!(matches!(
            validate_public_path("/hsin_tiao"),
            Ok(RouteNamespace::Custom)
        ));
        assert!(matches!(
            validate_public_path("/api/wechat-ws"),
            Ok(RouteNamespace::Custom)
        ));
        assert!(matches!(
            validate_public_path("/api/pc/socket"),
            Ok(RouteNamespace::Pc)
        ));
    }

    #[test]
    fn unsafe_or_ambiguous_paths_remain_rejected() {
        for path in ["relative", "/a//b", "/a/../b", "/a/./b", "/a?x=1", "/a#frag", "/a\\b"] {
            assert!(
                validate_public_path(path).is_err(),
                "{path:?} should be rejected"
            );
        }
    }

    #[test]
    fn websocket_backend_remains_supported() {
        let parsed = BackendEndpoint::parse("ws://127.0.0.1:9000/socket");
        assert!(parsed.is_ok());
        let Ok(backend) = parsed else {
            return;
        };
        assert_eq!(backend.kind(), BackendKind::WebSocket);
        assert_eq!(backend.address().to_string(), "127.0.0.1:9000");
        assert_eq!(
            backend.websocket().map(|endpoint| endpoint.request_target().to_string()),
            Some("/socket".to_owned())
        );
    }

    #[test]
    fn tcp_backend_is_supported_without_protocol_rewrapping() {
        let parsed = BackendEndpoint::parse("tcp://127.0.0.1:33301");
        assert!(parsed.is_ok());
        let Ok(backend) = parsed else {
            return;
        };
        assert_eq!(backend.kind(), BackendKind::Tcp);
        assert_eq!(backend.address().to_string(), "127.0.0.1:33301");
        assert!(backend.websocket().is_none());
    }

    #[test]
    fn tcp_backend_requires_loopback_explicit_port_and_no_path() {
        for backend in [
            "tcp://127.0.0.1",
            "tcp://10.0.0.1:33301",
            "tcp://127.0.0.1:33301/path",
            "tcp://127.0.0.1:33301/?x=1",
        ] {
            assert!(
                BackendEndpoint::parse(backend).is_err(),
                "{backend:?} should be rejected"
            );
        }
    }
}
