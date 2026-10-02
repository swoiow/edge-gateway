use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hyper::HeaderMap;
use serde::Deserialize;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::cloudflare::CloudflareNetworks;
use super::network::{IpNetwork, normalize_ip};

/// Origin admission belongs to the selected route, not the shared listener.
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteSecurity {
    #[serde(default)]
    pub(crate) cloudflare_only: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct ResolvedClientAddress {
    pub(crate) peer: SocketAddr,
    pub(crate) client_ip: IpAddr,
    pub(crate) client_ip_source: &'static str,
    pub(crate) trusted_proxy: bool,
}

pub(crate) struct ClientAddressPolicy {
    cloudflare: Arc<CloudflareNetworks>,
    health_peer_networks: Vec<IpNetwork>,
}

impl ClientAddressPolicy {
    pub(crate) fn new(
        cloudflare: Arc<CloudflareNetworks>,
        health_peer_networks: Vec<IpNetwork>,
    ) -> Self {
        Self {
            cloudflare,
            health_peer_networks,
        }
    }

    pub(crate) fn start(&self, shutdown: CancellationToken) -> JoinHandle<()> {
        self.cloudflare.start(shutdown)
    }

    pub(crate) fn permits_health_peer(&self, peer: SocketAddr) -> bool {
        self.health_peer_networks.iter().any(|n| n.contains(peer.ip()))
    }

    pub(crate) fn resolve_client_address(
        &self,
        peer: SocketAddr,
        headers: &HeaderMap,
        security: RouteSecurity,
    ) -> Result<ResolvedClientAddress, &'static str> {
        let trusted_proxy = self.cloudflare.contains(peer.ip());
        if !trusted_proxy {
            if security.cloudflare_only {
                return Err("route requires a Cloudflare origin peer");
            }
            return Ok(ResolvedClientAddress {
                peer,
                client_ip: normalize_ip(peer.ip()),
                client_ip_source: "direct_peer",
                trusted_proxy: false,
            });
        }
        let mut values = headers.get_all("cf-connecting-ip").iter();
        let value = values.next().ok_or("missing CF-Connecting-IP from trusted CF peer")?;
        if values.next().is_some() {
            return Err("multiple CF-Connecting-IP headers");
        }
        let address = value
            .to_str()
            .map_err(|_| "invalid CF-Connecting-IP")?
            .parse::<IpAddr>()
            .map_err(|_| "invalid CF-Connecting-IP")?;
        Ok(ResolvedClientAddress {
            peer,
            client_ip: normalize_ip(address),
            client_ip_source: "cf_connecting_ip",
            trusted_proxy: true,
        })
    }
}

pub(crate) fn sanitize_client_address_headers(
    headers: &mut HeaderMap,
    address: ResolvedClientAddress,
) {
    let mut protocols = headers.get_all("x-forwarded-proto").iter();
    let protocol = protocols.next().and_then(|value| value.to_str().ok());
    let is_http = address.trusted_proxy && protocol == Some("http") && protocols.next().is_none();
    let internal: Vec<_> = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-edge-gateway-")
                || name.as_str().starts_with("x-forwarded-")
        })
        .cloned()
        .collect();
    for name in internal {
        headers.remove(name);
    }
    for name in [
        "cf-connecting-ip",
        "cf-connecting-ipv6",
        "true-client-ip",
        "x-real-ip",
        "forwarded",
        "x-original-url",
        "x-rewrite-url",
    ] {
        headers.remove(name);
    }
    if !address.trusted_proxy {
        let cf_headers: Vec<_> = headers
            .keys()
            .filter(|name| name.as_str().starts_with("cf-"))
            .cloned()
            .collect();
        for name in cf_headers {
            headers.remove(name);
        }
    }
    if let Ok(value) = hyper::header::HeaderValue::from_str(&address.client_ip.to_string()) {
        headers.insert("x-forwarded-for", value.clone());
        headers.insert("x-real-ip", value.clone());
        if address.trusted_proxy {
            headers.insert("cf-connecting-ip", value);
        }
    }
    headers.insert(
        "x-forwarded-proto",
        hyper::header::HeaderValue::from_static(if is_http { "http" } else { "https" }),
    );
}
