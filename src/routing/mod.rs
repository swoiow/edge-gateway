use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use hyper::header::HOST;
use hyper::{Request, Version};

/// Configuration and request hosts use DNS ASCII names (IDNs must use punycode).
/// A single terminal dot is canonicalized; ports never participate in routing.
pub(crate) fn normalize_dns_host(value: &str) -> Result<String, &'static str> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err("host must be an ASCII DNS name between 1 and 253 bytes");
    }
    if value.parse::<IpAddr>().is_ok() {
        return Err("IP literal routing hosts are not supported");
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("host contains an invalid DNS label; wildcards are not supported");
        }
    }
    Ok(value.to_ascii_lowercase())
}

fn normalize_authority(value: &str) -> Result<(String, Option<u16>), &'static str> {
    let (host, port) = match value.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid authority port");
            }
            let port = port.parse::<u16>().map_err(|_| "invalid authority port")?;
            if port == 0 {
                return Err("authority port must not be zero");
            }
            (host, Some(port))
        }
        None => (value, None),
    };
    Ok((normalize_dns_host(host)?, port))
}

pub(crate) fn resolve_request_host<B>(request: &Request<B>) -> Result<String, &'static str> {
    let mut hosts = request.headers().get_all(HOST).iter();
    let header = hosts
        .next()
        .map(|h| h.to_str().map_err(|_| "invalid Host header"))
        .transpose()?;
    if hosts.next().is_some() {
        return Err("multiple Host headers");
    }
    let uri_authority = request.uri().authority().map(|a| a.as_str());
    let header = header.map(normalize_authority).transpose()?;
    let authority = uri_authority.map(normalize_authority).transpose()?;
    if let (Some(header), Some(authority)) = (&header, &authority) {
        // HTTPS port omission is equivalent to :443. Other ports must agree.
        if header.0 != authority.0 || header.1.unwrap_or(443) != authority.1.unwrap_or(443) {
            return Err("Host header conflicts with request authority");
        }
    }
    if request.version() == Version::HTTP_2 && authority.is_none() {
        return Err("HTTP/2 :authority is required");
    }
    authority.or(header).map(|v| v.0).ok_or("request authority is required")
}

pub(crate) struct RoutingPolicy {
    hosts: HashSet<String>,
    require_sni: bool,
    sni_bindings: HashMap<String, HashSet<String>>,
}

impl RoutingPolicy {
    pub(crate) fn build(
        hosts: HashSet<String>,
        require_sni: bool,
        bindings: Vec<(String, Vec<String>)>,
    ) -> Result<Self, String> {
        let mut sni_bindings = HashMap::new();
        for (sni, targets) in bindings {
            let sni = normalize_dns_host(&sni).map_err(str::to_owned)?;
            if targets.is_empty() {
                return Err(format!("SNI {sni} has no allowed hosts"));
            }
            let mut allowed = HashSet::new();
            for target in targets {
                let target = normalize_dns_host(&target).map_err(str::to_owned)?;
                if !hosts.contains(&target) {
                    return Err(format!("SNI {sni} references unconfigured host {target}"));
                }
                if !allowed.insert(target.clone()) {
                    return Err(format!("duplicate host {target} in SNI {sni}"));
                }
            }
            if sni_bindings.insert(sni.clone(), allowed).is_some() {
                return Err(format!("duplicate SNI binding {sni}"));
            }
        }
        Ok(Self {
            hosts,
            require_sni,
            sni_bindings,
        })
    }

    pub(crate) fn permits_request_host(&self, host: &str, sni: Option<&str>) -> bool {
        if !self.hosts.contains(host) {
            return false;
        }
        match sni {
            None => !self.require_sni,
            Some(sni) => {
                let Ok(sni) = normalize_dns_host(sni) else {
                    return false;
                };
                if let Some(allowed) = self.sni_bindings.get(&sni) {
                    return allowed.contains(host);
                }
                sni == host
            }
        }
    }
}
