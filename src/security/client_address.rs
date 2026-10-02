use std::net::{IpAddr, SocketAddr};

use hyper::HeaderMap;
use serde::Deserialize;

use super::network::{IpNetwork, normalize_ip};

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ClientIpMode {
    Cloudflare,
    Direct,
}

#[derive(Clone, Copy)]
pub(crate) struct ResolvedClientAddress {
    pub(crate) peer: SocketAddr,
    pub(crate) client_ip: IpAddr,
    pub(crate) client_ip_source: &'static str,
    pub(crate) trusted_proxy: bool,
}

pub(crate) struct ClientAddressPolicy {
    mode: ClientIpMode,
    trusted_proxy_networks: Vec<IpNetwork>,
    health_peer_networks: Vec<IpNetwork>,
}

impl ClientAddressPolicy {
    pub(crate) fn new(
        mode: ClientIpMode,
        trusted_proxy_networks: Vec<IpNetwork>,
        health_peer_networks: Vec<IpNetwork>,
    ) -> Self {
        Self {
            mode,
            trusted_proxy_networks,
            health_peer_networks,
        }
    }

    fn is_trusted_proxy(&self, peer: SocketAddr) -> bool {
        self.mode == ClientIpMode::Cloudflare
            && self.trusted_proxy_networks.iter().any(|n| n.contains(peer.ip()))
    }

    pub(crate) fn permits_health_peer(&self, peer: SocketAddr) -> bool {
        self.health_peer_networks.iter().any(|n| n.contains(peer.ip()))
    }

    pub(crate) fn permits_transport_peer(&self, peer: SocketAddr) -> bool {
        self.mode == ClientIpMode::Direct
            || self.is_trusted_proxy(peer)
            || self.permits_health_peer(peer)
    }

    pub(crate) fn resolve_trusted_client_address(
        &self,
        peer: SocketAddr,
        headers: &HeaderMap,
    ) -> Result<ResolvedClientAddress, &'static str> {
        if self.mode == ClientIpMode::Direct {
            return Ok(ResolvedClientAddress {
                peer,
                client_ip: normalize_ip(peer.ip()),
                client_ip_source: "direct_peer",
                trusted_proxy: false,
            });
        }
        if !self.is_trusted_proxy(peer) {
            return Err("untrusted origin peer");
        }
        let mut values = headers.get_all("cf-connecting-ip").iter();
        let value = values.next().ok_or("missing CF-Connecting-IP")?;
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

/// Backends see gateway-verified identity rather than an untrusted address chain.
pub(crate) fn sanitize_client_address_headers(
    headers: &mut HeaderMap,
    address: ResolvedClientAddress,
) {
    for name in [
        "cf-connecting-ip",
        "cf-connecting-ipv6",
        "true-client-ip",
        "x-forwarded-for",
        "x-real-ip",
        "forwarded",
    ] {
        headers.remove(name);
    }
    if let Ok(value) = hyper::header::HeaderValue::from_str(&address.client_ip.to_string()) {
        headers.insert("x-forwarded-for", value.clone());
        headers.insert("x-real-ip", value.clone());
        if address.trusted_proxy {
            headers.insert("cf-connecting-ip", value);
        }
    }
    let mut protocols = headers.get_all("x-forwarded-proto").iter();
    let protocol = protocols.next().and_then(|value| value.to_str().ok());
    let is_http = address.trusted_proxy && protocol == Some("http") && protocols.next().is_none();
    headers.insert(
        "x-forwarded-proto",
        hyper::header::HeaderValue::from_static(if is_http { "http" } else { "https" }),
    );
}
