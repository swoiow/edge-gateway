use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use hyper::Uri;
use serde::Deserialize;

use super::config::{FileUpstreamConfig, UpstreamConfig};
use crate::routing::normalize_dns_host;
use crate::security::RouteSecurity;

#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PathMatch {
    #[default]
    Exact,
    Prefix,
}
#[derive(Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Rewrite {
    #[default]
    Preserve,
    StripPrefix,
    ReplacePrefix,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileHttpRouteConfig {
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) path: String,
    #[serde(rename = "match", default)]
    pub(crate) path_match: PathMatch,
    #[serde(default)]
    pub(crate) rewrite: Rewrite,
    #[serde(default)]
    pub(crate) replacement_prefix: Option<String>,
    #[serde(default = "enabled_by_default")]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) security: RouteSecurity,
    pub(crate) upstream: FileUpstreamConfig,
}
const fn enabled_by_default() -> bool {
    true
}

pub(crate) struct HttpRoute {
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) path_match: PathMatch,
    pub(crate) rewrite: Rewrite,
    pub(crate) replacement_prefix: Option<String>,
    pub(crate) security: RouteSecurity,
    pub(crate) upstream: UpstreamConfig,
}

impl HttpRoute {
    pub(crate) fn rewrite_target(&self, uri: &Uri) -> Result<String, &'static str> {
        validate_http_path(uri.path())?;
        let path = match self.rewrite {
            Rewrite::Preserve => uri.path().to_owned(),
            Rewrite::StripPrefix | Rewrite::ReplacePrefix => {
                let suffix = uri.path().strip_prefix(&self.path).ok_or("route does not match")?;
                let prefix = if self.rewrite == Rewrite::ReplacePrefix {
                    self.replacement_prefix.as_deref().unwrap_or("")
                } else {
                    ""
                };
                let result = format!("{prefix}{suffix}");
                if result.is_empty() {
                    "/".to_owned()
                } else {
                    result
                }
            }
        };
        Ok(match uri.query() {
            Some(query) => format!("{path}?{query}"),
            None => path,
        })
    }
}

struct HostRoutes {
    exact: HashMap<String, Arc<HttpRoute>>,
    prefixes: HashMap<String, Arc<HttpRoute>>,
}
pub(crate) struct HttpRouteTable {
    by_host: HashMap<String, HostRoutes>,
    configured_count: usize,
    enabled_count: usize,
}
impl HttpRouteTable {
    pub(crate) fn build(
        specs: Vec<FileHttpRouteConfig>,
        directory: &Path,
        reserved: &HashSet<(String, String)>,
    ) -> Result<Self, String> {
        if specs.len() > 4096 {
            return Err("http_routes exceeds 4096 entries".to_owned());
        }
        let configured_count = specs.len();
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        let mut by_host: HashMap<String, HostRoutes> = HashMap::new();
        let mut enabled_count = 0;
        for spec in specs {
            if spec.id.is_empty()
                || spec.id.len() > 128
                || spec.id.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(
                    "http_routes.id must be 1..128 bytes without control/whitespace".to_owned(),
                );
            }
            if !ids.insert(spec.id.clone()) {
                return Err(format!("duplicate HTTP route id {}", spec.id));
            }
            let host = normalize_dns_host(&spec.host).map_err(str::to_owned)?;
            validate_http_path(&spec.path).map_err(str::to_owned)?;
            if matches!(spec.path.as_str(), "/health/live" | "/health/ready") {
                return Err("HTTP route uses a reserved health path".to_owned());
            }
            if spec.path_match == PathMatch::Prefix && spec.path != "/" && spec.path.ends_with('/')
            {
                return Err("segment prefixes must not end in slash (except /)".to_owned());
            }
            let key = (
                host.clone(),
                spec.path.clone(),
                spec.path_match == PathMatch::Prefix,
            );
            if !keys.insert(key) {
                return Err(format!("duplicate HTTP match at {host}{}", spec.path));
            }
            if spec.path_match == PathMatch::Exact
                && reserved.contains(&(host.clone(), spec.path.clone()))
            {
                return Err(format!(
                    "HTTP route at {host}{} is shadowed by an explicit WS/gRPC route",
                    spec.path
                ));
            }
            if spec.rewrite == Rewrite::StripPrefix
                && (spec.path_match != PathMatch::Prefix || spec.path == "/")
            {
                return Err("strip_prefix requires a non-root segment prefix match".to_owned());
            }
            match (spec.rewrite, &spec.replacement_prefix) {
                (Rewrite::ReplacePrefix, Some(prefix)) => {
                    validate_http_path(prefix).map_err(str::to_owned)?;
                    if prefix.ends_with('/')
                        && !(prefix == "/" && spec.path_match == PathMatch::Exact)
                    {
                        return Err(
                            "replacement_prefix must not end in slash (except exact replacement /)"
                                .to_owned(),
                        );
                    }
                    if spec.path == "/" && spec.path_match == PathMatch::Prefix {
                        return Err(
                            "replace_prefix of / is ambiguous; use preserve or a non-root prefix"
                                .to_owned(),
                        );
                    }
                }
                (Rewrite::ReplacePrefix, None) => {
                    return Err("replace_prefix requires replacement_prefix".to_owned());
                }
                (_, Some(_)) => {
                    return Err("replacement_prefix is only valid with replace_prefix".to_owned());
                }
                _ => {}
            }
            let upstream = spec
                .upstream
                .validate(directory)
                .map_err(|error| format!("HTTP route {}: {error}", spec.id))?;
            if spec.enabled {
                let route = Arc::new(HttpRoute {
                    id: spec.id,
                    host: host.clone(),
                    path: spec.path,
                    path_match: spec.path_match,
                    rewrite: spec.rewrite,
                    replacement_prefix: spec.replacement_prefix,
                    security: spec.security,
                    upstream,
                });
                let routes = by_host.entry(host).or_insert_with(|| HostRoutes {
                    exact: HashMap::new(),
                    prefixes: HashMap::new(),
                });
                match route.path_match {
                    PathMatch::Exact => {
                        routes.exact.insert(route.path.clone(), route);
                    }
                    PathMatch::Prefix => {
                        routes.prefixes.insert(route.path.clone(), route);
                    }
                }
                enabled_count += 1;
            }
        }
        Ok(Self {
            by_host,
            configured_count,
            enabled_count,
        })
    }
    pub(crate) fn resolve(&self, host: &str, path: &str) -> Option<Arc<HttpRoute>> {
        let routes = self.by_host.get(host)?;
        if let Some(route) = routes.exact.get(path) {
            return Some(Arc::clone(route));
        }
        let mut candidate = path;
        loop {
            if let Some(route) = routes.prefixes.get(candidate) {
                return Some(Arc::clone(route));
            }
            let slash = candidate.rfind('/')?;
            if slash == 0 {
                return routes.prefixes.get("/").cloned();
            }
            candidate = &candidate[..slash];
        }
    }
    pub(crate) fn hosts(&self) -> impl Iterator<Item = &String> {
        self.by_host.keys()
    }
    pub(crate) fn enabled_routes(&self) -> impl Iterator<Item = &Arc<HttpRoute>> {
        self.by_host
            .values()
            .flat_map(|routes| routes.exact.values().chain(routes.prefixes.values()))
    }
    pub(crate) fn configured_count(&self) -> usize {
        self.configured_count
    }
    pub(crate) fn enabled_count(&self) -> usize {
        self.enabled_count
    }
}

/// No decoding/normalization before matching: reject traversal and separator aliases.
/// All other percent encodings, case and the query are preserved byte-for-byte.
pub(crate) fn validate_http_path(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/')
        || path.len() > 8192
        || path.contains(['?', '#', '\\'])
        || path.bytes().any(|b| b <= b' ' || b == 127)
    {
        return Err("invalid HTTP path");
    }
    if path.contains("//") {
        return Err("repeated path separators are not supported");
    }
    for segment in path.split('/') {
        if matches!(segment, "." | "..") {
            return Err("dot segments are not supported");
        }
        let bytes = segment.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                if index + 2 >= bytes.len() {
                    return Err("invalid percent encoding");
                }
                let high =
                    (bytes[index + 1] as char).to_digit(16).ok_or("invalid percent encoding")?;
                let low =
                    (bytes[index + 2] as char).to_digit(16).ok_or("invalid percent encoding")?;
                let value = (high * 16 + low) as u8;
                // Encoded unreserved bytes could alias another route after backend decoding.
                if matches!(value, b'/' | b'\\' | b'%')
                    || value.is_ascii_alphanumeric()
                    || matches!(value, b'-' | b'.' | b'_' | b'~')
                    || value < b' '
                    || value == 127
                {
                    return Err(
                        "encoded path separators/unreserved/control/double encoding are not supported",
                    );
                }
                index += 3;
            } else {
                index += 1;
            }
        }
    }
    Ok(())
}
