use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::header::{
    CONNECTION, CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue, TE, TRANSFER_ENCODING,
    UPGRADE,
};
use hyper::{Request, Response, StatusCode, Uri, Version, upgrade};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, warn};

use crate::config::{FallbackConfig, FallbackScheme, FallbackTlsServerName};
use crate::gateway::body::{self, ResponseBody};

#[derive(Clone)]
pub(crate) struct FallbackRuntime {
    config: Arc<FallbackConfig>,
    connect_timeout: Duration,
    tls_roots: Arc<RootCertStore>,
    shutdown: CancellationToken,
    tasks: TaskTracker,
}

impl FallbackRuntime {
    pub(crate) async fn new(
        config: FallbackConfig,
        connect_timeout: Duration,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = config.ca_file() {
            let pem = tokio::fs::read(path)
                .await
                .with_context(|| format!("failed to read fallback CA file {}", path.display()))?;
            let mut reader = BufReader::new(pem.as_slice());
            let certificates = rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .with_context(|| format!("failed to parse fallback CA file {}", path.display()))?;
            let (added, ignored) = roots.add_parsable_certificates(certificates);
            if added == 0 {
                bail!(
                    "fallback CA file {} contains no usable CA certificates",
                    path.display()
                );
            }
            if ignored > 0 {
                warn!(
                    ca_file = %path.display(),
                    ignored,
                    "fallback CA file contained certificates that could not be used as trust anchors"
                );
            }
        }

        Ok(Self {
            config: Arc::new(config),
            connect_timeout,
            tls_roots: Arc::new(roots),
            shutdown,
            tasks: TaskTracker::new(),
        })
    }

    pub(crate) async fn proxy(
        &self,
        mut request: Request<Incoming>,
        peer: SocketAddr,
        transport_connection_id: u64,
        downstream_sni: Option<&str>,
    ) -> Response<ResponseBody> {
        if self.shutdown.is_cancelled() {
            return text_response(StatusCode::SERVICE_UNAVAILABLE, "gateway shutting down\n");
        }

        let request_version = request.version();
        let is_upgrade = is_http1_upgrade(&request);
        let host = match request_authority(&request) {
            Ok(host) => host,
            Err(error) => {
                warn!(
                    transport_connection_id,
                    %peer,
                    error = %error,
                    "fallback request has no usable authority"
                );
                return text_response(StatusCode::BAD_REQUEST, "host/authority required\n");
            }
        };
        let tls_name = match self.resolve_tls_server_name(downstream_sni, &host) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    transport_connection_id,
                    %peer,
                    error = %error,
                    "fallback TLS server-name resolution failed"
                );
                return text_response(StatusCode::BAD_GATEWAY, "fallback TLS name invalid\n");
            }
        };

        if self.config.preserve_host() {
            match HeaderValue::from_str(&host) {
                Ok(value) => {
                    request.headers_mut().insert(HOST, value);
                }
                Err(error) => {
                    warn!(
                        transport_connection_id,
                        %peer,
                        error = %error,
                        "fallback request authority is not a valid Host header"
                    );
                    return text_response(StatusCode::BAD_REQUEST, "invalid host/authority\n");
                }
            }
        } else {
            let backend_host = self.config.address().to_string();
            match HeaderValue::from_str(&backend_host) {
                Ok(value) => {
                    request.headers_mut().insert(HOST, value);
                }
                Err(error) => {
                    warn!(error = %error, "failed to construct fallback backend Host header");
                    return text_response(
                        StatusCode::BAD_GATEWAY,
                        "fallback configuration invalid\n",
                    );
                }
            }
        }

        if is_upgrade {
            sanitize_upgrade_headers(request.headers_mut());
        } else {
            sanitize_request_headers(request.headers_mut(), request_version);
        }

        debug!(
            transport_connection_id,
            %peer,
            backend = self.config.backend(),
            request_host = %host,
            downstream_sni = downstream_sni.unwrap_or("-"),
            http_version = ?request_version,
            method = %request.method(),
            path = %request.uri().path(),
            "request falling back to nginx-compatible upstream"
        );

        let upstream_authority = if self.config.preserve_host() {
            host.clone()
        } else {
            self.config.address().to_string()
        };

        let result = match request_version {
            Version::HTTP_2 => self.proxy_http2(request, &upstream_authority, tls_name).await,
            Version::HTTP_10 | Version::HTTP_11 => {
                self.proxy_http1(request, is_upgrade, tls_name).await
            }
            _ => Err(anyhow!(
                "fallback supports downstream HTTP/1.x and HTTP/2 only"
            )),
        };

        match result {
            Ok(response) => response,
            Err(error) => {
                warn!(
                    transport_connection_id,
                    %peer,
                    backend = self.config.backend(),
                    error = %error,
                    "fallback upstream request failed"
                );
                text_response(StatusCode::BAD_GATEWAY, "fallback upstream unavailable\n")
            }
        }
    }

    async fn proxy_http1(
        &self,
        request: Request<Incoming>,
        is_upgrade: bool,
        tls_name: Option<String>,
    ) -> Result<Response<ResponseBody>> {
        let stream = self.connect_tcp().await?;
        match self.config.scheme() {
            FallbackScheme::Http => self.proxy_http1_io(request, is_upgrade, stream).await,
            FallbackScheme::Https => {
                let tls = self.connect_tls(stream, tls_name, vec![b"http/1.1".to_vec()]).await?;
                self.proxy_http1_io(request, is_upgrade, tls).await
            }
        }
    }

    async fn proxy_http1_io<IO>(
        &self,
        mut request: Request<Incoming>,
        is_upgrade: bool,
        io: IO,
    ) -> Result<Response<ResponseBody>>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let path_and_query = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .parse::<Uri>()
            .context("failed to construct fallback HTTP/1 request target")?;
        *request.uri_mut() = path_and_query;

        let downstream_upgrade = is_upgrade.then(|| upgrade::on(&mut request));
        let (mut sender, connection) = timeout(
            self.connect_timeout,
            http1::handshake::<_, Incoming>(TokioIo::new(io)),
        )
        .await
        .context("fallback HTTP/1 handshake timed out")?
        .context("fallback HTTP/1 handshake failed")?;

        let driver = if is_upgrade {
            self.tasks.spawn(async move {
                if let Err(error) = connection.with_upgrades().await {
                    debug!(error = %error, "fallback HTTP/1 upstream connection closed with error");
                }
            })
        } else {
            self.tasks.spawn(async move {
                if let Err(error) = connection.await {
                    debug!(error = %error, "fallback HTTP/1 upstream connection closed with error");
                }
            })
        };
        std::mem::drop(driver);

        let mut response =
            sender.send_request(request).await.context("fallback HTTP/1 request failed")?;

        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            sanitize_upgrade_headers(response.headers_mut());
        } else {
            sanitize_response_headers(response.headers_mut());
        }

        if let Some(downstream_upgrade) = downstream_upgrade {
            if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                let upstream_upgrade = upgrade::on(&mut response);
                let shutdown = self.shutdown.child_token();
                let tunnel = self.tasks.spawn(async move {
                    let (downstream, upstream) = tokio::join!(downstream_upgrade, upstream_upgrade);
                    let (Ok(downstream), Ok(upstream)) = (downstream, upstream) else {
                        warn!("fallback HTTP upgrade did not complete on both sides");
                        return;
                    };
                    let mut downstream = TokioIo::new(downstream);
                    let mut upstream = TokioIo::new(upstream);
                    tokio::select! {
                        result = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => {
                            match result {
                                Ok((client_to_upstream, upstream_to_client)) => {
                                    debug!(client_to_upstream, upstream_to_client, "fallback upgraded tunnel closed");
                                }
                                Err(error) => {
                                    debug!(error = %error, "fallback upgraded tunnel failed");
                                }
                            }
                        }
                        () = shutdown.cancelled() => {
                            debug!("fallback upgraded tunnel cancelled during gateway shutdown");
                        }
                    }
                });
                std::mem::drop(tunnel);
            }
        }

        Ok(response.map(body::boxed))
    }

    async fn proxy_http2(
        &self,
        request: Request<Incoming>,
        request_host: &str,
        tls_name: Option<String>,
    ) -> Result<Response<ResponseBody>> {
        let stream = self.connect_tcp().await?;
        match self.config.scheme() {
            FallbackScheme::Http => self.proxy_http2_io(request, request_host, stream).await,
            FallbackScheme::Https => {
                let tls = self.connect_tls(stream, tls_name, vec![b"h2".to_vec()]).await?;
                self.proxy_http2_io(request, request_host, tls).await
            }
        }
    }

    async fn proxy_http2_io<IO>(
        &self,
        mut request: Request<Incoming>,
        request_host: &str,
        io: IO,
    ) -> Result<Response<ResponseBody>>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let path = request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/");
        let scheme = match self.config.scheme() {
            FallbackScheme::Http => "http",
            FallbackScheme::Https => "https",
        };
        *request.uri_mut() = format!("{scheme}://{request_host}{path}")
            .parse::<Uri>()
            .context("failed to construct fallback HTTP/2 URI")?;
        // HTTP/2 carries the virtual host in :authority. Avoid sending a second Host field.
        request.headers_mut().remove(HOST);

        let (mut sender, connection) = timeout(
            self.connect_timeout,
            http2::handshake::<_, _, Incoming>(TokioExecutor::new(), TokioIo::new(io)),
        )
        .await
        .context("fallback HTTP/2 handshake timed out")?
        .context("fallback HTTP/2 handshake failed")?;
        let driver = self.tasks.spawn(async move {
            if let Err(error) = connection.await {
                debug!(error = %error, "fallback HTTP/2 upstream connection closed with error");
            }
        });
        std::mem::drop(driver);

        let mut response =
            sender.send_request(request).await.context("fallback HTTP/2 request failed")?;
        sanitize_response_headers(response.headers_mut());
        Ok(response.map(body::boxed))
    }

    async fn connect_tcp(&self) -> Result<TcpStream> {
        let stream = timeout(
            self.connect_timeout,
            TcpStream::connect(self.config.address()),
        )
        .await
        .with_context(|| {
            format!(
                "fallback TCP connect to {} timed out",
                self.config.address()
            )
        })?
        .with_context(|| format!("failed to connect to fallback {}", self.config.backend()))?;
        stream
            .set_nodelay(true)
            .context("failed to enable TCP_NODELAY for fallback upstream")?;
        Ok(stream)
    }

    async fn connect_tls(
        &self,
        stream: TcpStream,
        tls_name: Option<String>,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tls_name =
            tls_name.ok_or_else(|| anyhow!("fallback HTTPS requires a TLS server name"))?;
        let server_name = ServerName::try_from(tls_name.clone())
            .map_err(|_| anyhow!("invalid fallback TLS server name {tls_name:?}"))?;
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(Arc::clone(&self.tls_roots))
            .with_no_client_auth();
        client_config.alpn_protocols = alpn_protocols;
        let connector = TlsConnector::from(Arc::new(client_config));
        let tls = timeout(self.connect_timeout, connector.connect(server_name, stream))
            .await
            .context("fallback TLS handshake timed out")?
            .context("fallback TLS handshake failed")?;
        Ok(tls)
    }

    fn resolve_tls_server_name(
        &self,
        downstream_sni: Option<&str>,
        request_host: &str,
    ) -> Result<Option<String>> {
        if self.config.scheme() == FallbackScheme::Http {
            return Ok(None);
        }
        let name = match self.config.tls_server_name() {
            FallbackTlsServerName::RequestHost => downstream_sni
                .map(str::to_owned)
                .unwrap_or_else(|| strip_port(request_host).to_owned()),
            FallbackTlsServerName::Literal(name) => name.clone(),
        };
        if name.is_empty() {
            bail!("fallback TLS server name is empty");
        }
        Ok(Some(name))
    }

    pub(crate) fn close(&self) {
        self.tasks.close();
    }

    pub(crate) async fn wait(&self) {
        self.tasks.wait().await;
    }
}

fn sanitize_upgrade_headers(headers: &mut HeaderMap) {
    let connection_names = connection_named_headers(headers);
    for name in connection_names {
        if name != UPGRADE {
            headers.remove(name);
        }
    }
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.remove(TE);
    headers.remove(TRANSFER_ENCODING);
    headers.remove("proxy-connection");
    headers.remove("keep-alive");
}

fn sanitize_request_headers(headers: &mut HeaderMap, version: Version) {
    remove_connection_named_headers(headers);
    headers.remove(CONNECTION);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
    headers.remove("proxy-connection");
    headers.remove("keep-alive");
    let keep_te_trailers = version == Version::HTTP_2
        && headers
            .get(TE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("trailers"));
    if !keep_te_trailers {
        headers.remove(TE);
    }
}

fn sanitize_response_headers(headers: &mut HeaderMap) {
    remove_connection_named_headers(headers);
    headers.remove(CONNECTION);
    headers.remove(TE);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
    headers.remove("proxy-connection");
    headers.remove("keep-alive");
}

fn connection_named_headers(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

fn remove_connection_named_headers(headers: &mut HeaderMap) {
    for name in connection_named_headers(headers) {
        headers.remove(name);
    }
}

fn request_authority(request: &Request<Incoming>) -> Result<String> {
    let uri_authority = request.uri().authority().map(|value| value.as_str());
    let host_header = request
        .headers()
        .get(HOST)
        .map(|value| value.to_str().context("Host header is not valid ASCII"))
        .transpose()?;

    if let (Some(uri_authority), Some(host_header)) = (uri_authority, host_header) {
        if !uri_authority.eq_ignore_ascii_case(host_header) {
            bail!("request URI authority and Host header do not match");
        }
    }

    let authority =
        uri_authority.or(host_header).ok_or_else(|| anyhow!("missing Host/authority"))?;
    if authority.is_empty() {
        bail!("Host/authority is empty");
    }
    Ok(authority.to_owned())
}

fn strip_port(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    authority.rsplit_once(':').map(|(host, _)| host).unwrap_or(authority)
}

fn is_http1_upgrade(request: &Request<Incoming>) -> bool {
    if request.version() != Version::HTTP_11 || !request.headers().contains_key(UPGRADE) {
        return false;
    }
    request
        .headers()
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
}

fn text_response(status: StatusCode, response_body: &'static str) -> Response<ResponseBody> {
    let mut response = Response::new(body::boxed(Full::new(Bytes::from_static(
        response_body.as_bytes(),
    ))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::strip_port;

    #[test]
    fn strips_host_ports_without_damaging_ipv6() {
        assert_eq!(strip_port("api.trip2w.com:443"), "api.trip2w.com");
        assert_eq!(strip_port("api.trip2w.com"), "api.trip2w.com");
        assert_eq!(strip_port("[::1]:443"), "::1");
    }
}
