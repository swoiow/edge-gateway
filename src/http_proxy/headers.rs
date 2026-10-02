use hyper::header::{CONNECTION, HOST, HeaderName, HeaderValue, TE, TRANSFER_ENCODING, UPGRADE};
use hyper::{HeaderMap, Request};

pub(crate) fn request_authority<B>(request: &Request<B>) -> Result<String, &'static str> {
    crate::routing::resolve_request_host(request)?;
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| request.headers().get(HOST).and_then(|value| value.to_str().ok()))
        .map(str::to_owned)
        .ok_or("request authority required")
}

pub(crate) fn sanitize_request(headers: &mut HeaderMap, upgrade: bool) {
    sanitize_hop_headers(headers, upgrade);
    headers.remove("proxy-authorization");
    headers.remove("proxy-authenticate");
    headers.remove(TE);
    // The gateway can preserve response trailers; advertise this to its upstream.
    if !upgrade {
        headers.insert(TE, HeaderValue::from_static("trailers"));
    }
}
pub(crate) fn sanitize_response(headers: &mut HeaderMap, upgrade: bool) {
    sanitize_hop_headers(headers, upgrade);
    headers.remove(TE);
    headers.remove("proxy-authenticate");
}
fn sanitize_hop_headers(headers: &mut HeaderMap, upgrade: bool) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        if !upgrade || name != UPGRADE {
            headers.remove(name);
        }
    }
    headers.remove(CONNECTION);
    if upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(UPGRADE);
    }
    for name in ["proxy-connection", "keep-alive", "transfer-encoding"] {
        headers.remove(name);
    }
    headers.remove(TRANSFER_ENCODING);
}

/// Routing, framing and identity cannot be redefined by late trailer fields.
pub(crate) fn sanitize_trailers(headers: &mut HeaderMap) {
    sanitize_hop_headers(headers, false);
    let identity: Vec<_> = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-forwarded-")
                || name.as_str().starts_with("x-edge-gateway-")
                || name.as_str().starts_with("cf-")
        })
        .cloned()
        .collect();
    for name in identity {
        headers.remove(name);
    }
    for name in [
        "host",
        "content-length",
        "content-type",
        "content-encoding",
        "trailer",
        "te",
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-real-ip",
        "forwarded",
        "true-client-ip",
        "x-original-url",
        "x-rewrite-url",
    ] {
        headers.remove(name);
    }
}

pub(crate) fn declared_trailer_names(
    headers: &HeaderMap,
) -> Result<std::collections::HashSet<HeaderName>, &'static str> {
    let mut names = std::collections::HashSet::new();
    for value in headers.get_all("trailer").iter() {
        for name in value.to_str().map_err(|_| "invalid Trailer declaration")?.split(',') {
            let name = HeaderName::from_bytes(name.trim().as_bytes())
                .map_err(|_| "invalid Trailer declaration")?;
            names.insert(name);
            if names.len() > 100 {
                return Err("too many declared trailers");
            }
        }
    }
    Ok(names)
}

pub(crate) fn sanitize_stream_frame(
    mut frame: hyper::body::Frame<bytes::Bytes>,
    declared: Option<&std::collections::HashSet<HeaderName>>,
) -> Result<hyper::body::Frame<bytes::Bytes>, crate::gateway::body::BoxError> {
    if let Some(trailers) = frame.trailers_mut() {
        let bytes = trailers.iter().fold(0usize, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
                .saturating_add(32)
        });
        if trailers.len() > 100 || bytes > 32768 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP trailer limit exceeded",
            )
            .into());
        }
        sanitize_trailers(trailers);
        if declared.is_some_and(|names| trailers.keys().any(|name| !names.contains(name))) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "H1 trailers require a prior Trailer header declaration",
            )
            .into());
        }
    }
    Ok(frame)
}
