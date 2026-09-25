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

pub(crate) struct BackendEndpoint {
    display: Arc<str>,
    address: SocketAddr,
    request_target: Uri,
    host_header: HeaderValue,
}

impl BackendEndpoint {
    fn parse(value: &str) -> Result<Self, RouteError> {
        let uri = value.parse::<Uri>().map_err(|source| RouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: source.to_string(),
        })?;

        if uri.scheme_str() != Some("ws") {
            return Err(RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: "scheme must be ws".to_owned(),
            });
        }

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

        let port = uri.port_u16().unwrap_or(80);
        let request_target = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .parse::<Uri>()
            .map_err(|source| RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: format!("invalid request target: {source}"),
            })?;
        let host_header = HeaderValue::from_str(authority.as_str()).map_err(|source| {
            RouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: format!("invalid authority: {source}"),
            }
        })?;

        Ok(Self {
            display: Arc::from(value),
            address: SocketAddr::new(ip, port),
            request_target,
            host_header,
        })
    }

    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn request_target(&self) -> &Uri {
        &self.request_target
    }

    pub(crate) fn host_header(&self) -> &HeaderValue {
        &self.host_header
    }
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
    use super::{RouteNamespace, validate_public_path};

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
}
