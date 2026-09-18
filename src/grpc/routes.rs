use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hyper::Uri;
use hyper::header::HeaderValue;
use thiserror::Error;

const MAX_ROUTE_ID_LENGTH: usize = 128;
const MAX_GRPC_PATH_LENGTH: usize = 2048;

pub(crate) struct GrpcRouteSpec {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) backend: String,
    pub(crate) enabled: bool,
}

pub(crate) struct GrpcRouteTable {
    enabled_by_path: HashMap<Arc<str>, Arc<GrpcRoute>>,
    configured_count: usize,
}

impl GrpcRouteTable {
    pub(crate) fn build(specs: Vec<GrpcRouteSpec>) -> Result<Self, GrpcRouteError> {
        let configured_count = specs.len();
        let mut ids = HashSet::with_capacity(configured_count);
        let mut paths = HashSet::with_capacity(configured_count);
        let mut enabled_by_path = HashMap::with_capacity(configured_count);

        for spec in specs {
            validate_id(&spec.id)?;
            validate_grpc_path(&spec.path)?;

            if !ids.insert(spec.id.clone()) {
                return Err(GrpcRouteError::DuplicateId(spec.id));
            }
            if !paths.insert(spec.path.clone()) {
                return Err(GrpcRouteError::DuplicatePath(spec.path));
            }

            let backend = GrpcBackendEndpoint::parse(&spec.backend)?;
            let upstream_uri = format!("http://{}{}", backend.authority(), spec.path)
                .parse::<Uri>()
                .map_err(|source| GrpcRouteError::InvalidBackend {
                    backend: spec.backend.clone(),
                    reason: format!("failed to build upstream HTTP/2 URI: {source}"),
                })?;

            if spec.enabled {
                let route = Arc::new(GrpcRoute {
                    id: Arc::from(spec.id),
                    path: Arc::from(spec.path),
                    backend,
                    upstream_uri,
                });
                enabled_by_path.insert(Arc::clone(&route.path), route);
            }
        }

        Ok(Self {
            enabled_by_path,
            configured_count,
        })
    }

    pub(crate) fn resolve(&self, path: &str) -> Option<Arc<GrpcRoute>> {
        self.enabled_by_path.get(path).cloned()
    }

    pub(crate) fn configured_count(&self) -> usize {
        self.configured_count
    }

    pub(crate) fn enabled_count(&self) -> usize {
        self.enabled_by_path.len()
    }

    pub(crate) fn enabled_routes(&self) -> impl Iterator<Item = &Arc<GrpcRoute>> {
        self.enabled_by_path.values()
    }
}

pub(crate) struct GrpcRoute {
    id: Arc<str>,
    path: Arc<str>,
    backend: GrpcBackendEndpoint,
    upstream_uri: Uri,
}

impl GrpcRoute {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn backend(&self) -> &GrpcBackendEndpoint {
        &self.backend
    }

    pub(crate) fn upstream_uri(&self) -> &Uri {
        &self.upstream_uri
    }
}

#[derive(Clone)]
pub(crate) struct GrpcBackendEndpoint {
    display: Arc<str>,
    address: SocketAddr,
    authority: Arc<str>,
    host_header: HeaderValue,
}

impl GrpcBackendEndpoint {
    fn parse(value: &str) -> Result<Self, GrpcRouteError> {
        let uri = value.parse::<Uri>().map_err(|source| GrpcRouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: source.to_string(),
        })?;

        if uri.scheme_str() != Some("h2c") {
            return Err(GrpcRouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: "scheme must be h2c".to_owned(),
            });
        }

        let authority = uri.authority().ok_or_else(|| GrpcRouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: "authority is required".to_owned(),
        })?;

        if authority.as_str().contains('@') {
            return Err(GrpcRouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: "userinfo is not allowed".to_owned(),
            });
        }

        let host = uri.host().ok_or_else(|| GrpcRouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: "host is required".to_owned(),
        })?;
        let ip = host.parse::<IpAddr>().map_err(|_| GrpcRouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: "host must be an IPv4 or IPv6 loopback address".to_owned(),
        })?;

        if !ip.is_loopback() {
            return Err(GrpcRouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: "host must be a loopback address".to_owned(),
            });
        }

        let port = uri.port_u16().ok_or_else(|| GrpcRouteError::InvalidBackend {
            backend: value.to_owned(),
            reason: "an explicit port is required".to_owned(),
        })?;
        let request_target = uri.path_and_query().map(|value| value.as_str()).unwrap_or("/");
        if request_target != "/" {
            return Err(GrpcRouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: "backend URL must not contain a path or query".to_owned(),
            });
        }

        let host_header = HeaderValue::from_str(authority.as_str()).map_err(|source| {
            GrpcRouteError::InvalidBackend {
                backend: value.to_owned(),
                reason: format!("invalid authority: {source}"),
            }
        })?;

        Ok(Self {
            display: Arc::from(value),
            address: SocketAddr::new(ip, port),
            authority: Arc::from(authority.as_str()),
            host_header,
        })
    }

    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    pub(crate) fn host_header(&self) -> &HeaderValue {
        &self.host_header
    }
}

#[derive(Debug, Error)]
pub(crate) enum GrpcRouteError {
    #[error("gRPC route id must not be empty")]
    EmptyId,
    #[error("gRPC route id {0:?} exceeds {MAX_ROUTE_ID_LENGTH} bytes")]
    IdTooLong(String),
    #[error("gRPC route id {0:?} contains control or whitespace characters")]
    InvalidId(String),
    #[error("gRPC route path {0:?} must use the exact /{{package}}.{{Service}}/{{Method}} form")]
    InvalidPath(String),
    #[error("gRPC route path {0:?} exceeds {MAX_GRPC_PATH_LENGTH} bytes")]
    PathTooLong(String),
    #[error("duplicate gRPC route id {0:?}")]
    DuplicateId(String),
    #[error("duplicate gRPC route path {0:?}")]
    DuplicatePath(String),
    #[error("invalid gRPC backend {backend:?}: {reason}")]
    InvalidBackend { backend: String, reason: String },
}

fn validate_id(id: &str) -> Result<(), GrpcRouteError> {
    if id.is_empty() {
        return Err(GrpcRouteError::EmptyId);
    }
    if id.len() > MAX_ROUTE_ID_LENGTH {
        return Err(GrpcRouteError::IdTooLong(id.to_owned()));
    }
    if id.chars().any(char::is_whitespace) || id.chars().any(char::is_control) {
        return Err(GrpcRouteError::InvalidId(id.to_owned()));
    }

    Ok(())
}

fn validate_grpc_path(path: &str) -> Result<(), GrpcRouteError> {
    if path.len() > MAX_GRPC_PATH_LENGTH {
        return Err(GrpcRouteError::PathTooLong(path.to_owned()));
    }
    if path.contains(['?', '#', '\\'])
        || path.chars().any(char::is_whitespace)
        || path.chars().any(char::is_control)
    {
        return Err(GrpcRouteError::InvalidPath(path.to_owned()));
    }

    let Some(remainder) = path.strip_prefix('/') else {
        return Err(GrpcRouteError::InvalidPath(path.to_owned()));
    };
    let mut segments = remainder.split('/');
    let Some(service) = segments.next() else {
        return Err(GrpcRouteError::InvalidPath(path.to_owned()));
    };
    let Some(method) = segments.next() else {
        return Err(GrpcRouteError::InvalidPath(path.to_owned()));
    };

    if segments.next().is_some()
        || service.is_empty()
        || method.is_empty()
        || !service.split('.').all(is_proto_identifier)
        || !is_proto_identifier(method)
    {
        return Err(GrpcRouteError::InvalidPath(path.to_owned()));
    }

    Ok(())
}

fn is_proto_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };

    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}
