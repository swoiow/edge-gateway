use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::network::IpNetwork;

const REFRESH_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_ENTRIES: usize = 4096;

/// Only the maintenance task performs file/network work. Requests load one snapshot.
pub(crate) struct CloudflareNetworks {
    networks: ArcSwap<Vec<IpNetwork>>,
    cache_file: Option<PathBuf>,
    connector: TlsConnector,
}

impl CloudflareNetworks {
    pub(crate) async fn load(cache_file: Option<PathBuf>) -> Result<Arc<Self>> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let runtime = Arc::new(Self {
            networks: ArcSwap::from_pointee(Vec::new()),
            cache_file,
            connector: TlsConnector::from(Arc::new(tls)),
        });
        if let Some(path) = &runtime.cache_file {
            match read_cache(path).await {
                Ok(networks) => runtime.networks.store(Arc::new(networks)),
                Err(error) => {
                    warn!(cache = %path.display(), %error, "CF cache absent/invalid; downloading before listener startup");
                    runtime
                        .refresh()
                        .await
                        .context("cannot establish initial Cloudflare CIDR snapshot")?;
                }
            }
        }
        Ok(runtime)
    }

    pub(crate) fn contains(&self, address: IpAddr) -> bool {
        self.networks.load().iter().any(|network| network.contains(address))
    }

    pub(crate) fn start(self: &Arc<Self>, shutdown: CancellationToken) -> JoinHandle<()> {
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            if runtime.cache_file.is_none() {
                return;
            }
            loop {
                let path = match &runtime.cache_file {
                    Some(path) => path,
                    None => return,
                };
                if cache_needs_refresh(path).await {
                    tokio::select! {
                        () = shutdown.cancelled() => return,
                        result = runtime.refresh() => {
                            if let Err(error) = result {
                                warn!(cache = %path.display(), %error, "CF refresh failed; retaining last valid snapshot; retry in one hour");
                            }
                        }
                    }
                }
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(RETRY_INTERVAL) => {}
                }
            }
        })
    }

    async fn refresh(&self) -> Result<()> {
        let Some(path) = &self.cache_file else {
            return Ok(());
        };
        // Both families must succeed and validate before publishing either family.
        let (v4, v6) = tokio::try_join!(
            self.download("/ips-v4", true),
            self.download("/ips-v6", false)
        )?;
        let source = format!(
            "# Managed by edge-gateway; official Cloudflare v4/v6 HTTPS sources\n{v4}\n{v6}\n"
        );
        let networks = parse_networks(&source)?;
        persist_cache(path, source.as_bytes()).await?;
        let count = networks.len();
        self.networks.store(Arc::new(networks));
        info!(cache = %path.display(), count, refresh_days = 30, "Cloudflare CIDR snapshot refreshed");
        Ok(())
    }

    async fn download(&self, path: &'static str, ipv4: bool) -> Result<String> {
        timeout(DOWNLOAD_TIMEOUT, async {
            let stream = TcpStream::connect(("www.cloudflare.com", 443)).await?;
            let name = ServerName::try_from("www.cloudflare.com")?;
            let tls = self.connector.connect(name, stream).await?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(tls)).await?;
            let request = Request::builder()
                .uri(path)
                .header("host", "www.cloudflare.com")
                .header(
                    "user-agent",
                    concat!("edge-gateway/", env!("CARGO_PKG_VERSION")),
                )
                .header("accept", "text/plain")
                .header("connection", "close")
                .body(Empty::<Bytes>::new())?;
            // Drive the connection in the same structured future; no orphan driver.
            let exchange = async {
                let response = sender.send_request(request).await?;
                if response.status() != StatusCode::OK {
                    bail!(
                        "CF CIDR download returned {} (redirects are not followed)",
                        response.status()
                    );
                }
                let mut body = response.into_body();
                let mut data = Vec::new();
                while let Some(frame) = body.frame().await {
                    let frame = frame?;
                    if let Some(bytes) = frame.data_ref() {
                        if data.len().saturating_add(bytes.len()) > MAX_FILE_BYTES {
                            bail!("CF CIDR response exceeds 256 KiB");
                        }
                        data.extend_from_slice(bytes);
                    }
                }
                let source = String::from_utf8(data)?;
                validate_family(&source, ipv4)?;
                Ok::<_, anyhow::Error>(source.trim().to_owned())
            };
            tokio::pin!(connection);
            tokio::pin!(exchange);
            tokio::select! {
                result = &mut exchange => result,
                result = &mut connection => {
                    result.context("CF download HTTP connection failed")?;
                    exchange.await
                }
            }
        })
        .await
        .context("CF CIDR download timed out")?
    }
}

fn validate_family(source: &str, ipv4: bool) -> Result<()> {
    let mut count = 0;
    for value in source.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (address, _) = value.split_once('/').context("CIDR prefix required")?;
        if address.parse::<IpAddr>()?.is_ipv4() != ipv4 {
            bail!("CF response contains the wrong IP family");
        }
        IpNetwork::parse(value).map_err(anyhow::Error::msg)?;
        count += 1;
        if count > MAX_ENTRIES {
            bail!("CF response has too many entries");
        }
    }
    if count == 0 {
        bail!("CF response is empty");
    }
    Ok(())
}

fn parse_networks(source: &str) -> Result<Vec<IpNetwork>> {
    if source.len() > MAX_FILE_BYTES {
        bail!("CF cache exceeds 256 KiB");
    }
    let mut seen = HashSet::new();
    let mut networks = Vec::new();
    let mut has_v4 = false;
    let mut has_v6 = false;
    for value in source
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
    {
        if !seen.insert(value) {
            bail!("duplicate CIDR in CF cache");
        }
        let address = value.split_once('/').context("CIDR prefix required")?.0.parse::<IpAddr>()?;
        has_v4 |= address.is_ipv4();
        has_v6 |= address.is_ipv6();
        networks.push(IpNetwork::parse(value).map_err(anyhow::Error::msg)?);
        if networks.len() > MAX_ENTRIES {
            bail!("CF cache has too many entries");
        }
    }
    if !has_v4 || !has_v6 {
        bail!("CF cache must contain both IP families");
    }
    Ok(networks)
}

async fn read_cache(path: &Path) -> Result<Vec<IpNetwork>> {
    let file = tokio::fs::File::open(path).await?;
    let mut source = String::new();
    file.take((MAX_FILE_BYTES + 1) as u64).read_to_string(&mut source).await?;
    parse_networks(&source)
}

async fn cache_needs_refresh(path: &Path) -> bool {
    match tokio::fs::metadata(path).await.and_then(|metadata| metadata.modified()) {
        Ok(modified) => match SystemTime::now().duration_since(modified) {
            Ok(age) => age >= REFRESH_AGE,
            Err(_) => true, // A future timestamp must not suppress refresh indefinitely.
        },
        Err(_) => true,
    }
}

async fn persist_cache(path: &Path, source: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    tokio::fs::create_dir_all(parent).await?;
    let name = path.file_name().context("CF cache requires a filename")?.to_string_lossy();
    let nonce = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_nanos();
    let temporary = parent.join(format!(".{name}.{}.{nonce}.tmp", std::process::id()));
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .await?;
    let result = async {
        file.write_all(source).await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, path).await?;
        Ok::<_, std::io::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result.context("failed to atomically persist CF CIDR cache")
}
