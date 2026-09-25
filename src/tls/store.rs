use std::collections::{HashMap, HashSet};
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use tokio::fs;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::resolver::DynamicCertResolver;
use crate::config::TlsConfig;

#[derive(Clone)]
pub(crate) struct CertificateMetadata {
    dns_names: Vec<String>,
    leaf_certificate: CertificateDer<'static>,
    not_after_unix: i64,
}

impl CertificateMetadata {
    pub(crate) fn dns_names(&self) -> &[String] {
        &self.dns_names
    }

    pub(crate) fn leaf_certificate(&self) -> &CertificateDer<'static> {
        &self.leaf_certificate
    }

    pub(crate) fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }
}

pub(super) struct CertificateIndex {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
    metadata: HashMap<String, CertificateMetadata>,
}

impl CertificateIndex {
    pub(super) fn exact_certificates(&self) -> &HashMap<String, Arc<CertifiedKey>> {
        &self.exact
    }

    pub(super) fn wildcard_certificates(&self) -> &HashMap<String, Arc<CertifiedKey>> {
        &self.wildcard
    }

    pub(super) fn default_certificate(&self) -> Option<Arc<CertifiedKey>> {
        self.default.clone()
    }

    pub(super) fn default_certificate_ref(&self) -> Option<&Arc<CertifiedKey>> {
        self.default.as_ref()
    }
}

#[derive(Clone)]
pub(crate) struct CertificateStore {
    config: TlsConfig,
    index: Arc<ArcSwap<CertificateIndex>>,
}

impl CertificateStore {
    pub(crate) async fn load(config: TlsConfig) -> Result<Self> {
        fs::create_dir_all(config.cert_dir()).await.with_context(|| {
            format!(
                "failed to create TLS certificate directory {}",
                config.cert_dir().display()
            )
        })?;
        let index = load_index(&config).await?;
        Ok(Self {
            config,
            index: Arc::new(ArcSwap::from_pointee(index)),
        })
    }

    pub(crate) async fn reload(&self) -> Result<()> {
        let new_index = load_index(&self.config).await?;
        self.index.store(Arc::new(new_index));
        Ok(())
    }

    pub(crate) fn resolver(&self) -> Arc<DynamicCertResolver> {
        Arc::new(DynamicCertResolver::new(Arc::clone(&self.index)))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.index.load().metadata.is_empty()
    }

    pub(crate) fn certificate_count(&self) -> usize {
        self.index.load().metadata.len()
    }

    pub(crate) fn metadata(&self, id: &str) -> Option<CertificateMetadata> {
        self.index.load().metadata.get(id).cloned()
    }

    pub(crate) fn validate_replacement(
        &self,
        id: &str,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<CertificateMetadata> {
        let (_, candidate) = parse_certificate_pair(id, certificate_pem, private_key_pem)?;
        let index = self.index.load();
        for (other_id, existing) in &index.metadata {
            if other_id == id {
                continue;
            }
            for name in candidate.dns_names() {
                if existing.dns_names().iter().any(|existing_name| existing_name == name) {
                    bail!(
                        "replacement TLS certificate {id:?} claims DNS SAN {name:?}, already owned by certificate {other_id:?}"
                    );
                }
            }
        }
        Ok(candidate)
    }

    pub(crate) fn default_certificate_available(&self) -> bool {
        match self.config.default_certificate() {
            Some(id) => self.index.load().metadata.contains_key(id),
            None => true,
        }
    }

    pub(crate) fn config(&self) -> &TlsConfig {
        &self.config
    }
}

async fn load_index(config: &TlsConfig) -> Result<CertificateIndex> {
    let pairs = discover_pairs(config).await?;
    let mut exact = HashMap::new();
    let mut wildcard = HashMap::new();
    let mut metadata = HashMap::new();
    let mut keys_by_id = HashMap::new();

    for (id, (cert_path, key_path)) in pairs {
        let certificate_bytes = fs::read(&cert_path)
            .await
            .with_context(|| format!("failed to read TLS certificate {}", cert_path.display()))?;
        let key_bytes = fs::read(&key_path)
            .await
            .with_context(|| format!("failed to read TLS private key {}", key_path.display()))?;
        let (certified_key, parsed) = parse_certificate_pair(&id, &certificate_bytes, &key_bytes)?;

        for name in &parsed.dns_names {
            if let Some(suffix) = name.strip_prefix("*.") {
                if wildcard.insert(suffix.to_owned(), Arc::clone(&certified_key)).is_some() {
                    bail!("more than one TLS certificate claims wildcard SAN {name:?}");
                }
            } else if exact.insert(name.clone(), Arc::clone(&certified_key)).is_some() {
                bail!("more than one TLS certificate claims DNS SAN {name:?}");
            }
        }

        keys_by_id.insert(id.clone(), certified_key);
        metadata.insert(id, parsed);
    }

    let default = config.default_certificate().and_then(|id| keys_by_id.get(id).cloned());

    Ok(CertificateIndex {
        exact,
        wildcard,
        default,
        metadata,
    })
}

async fn discover_pairs(
    config: &TlsConfig,
) -> Result<HashMap<String, (std::path::PathBuf, std::path::PathBuf)>> {
    let mut certs = HashMap::new();
    let mut keys = HashMap::new();
    let mut entries = fs::read_dir(config.cert_dir()).await.with_context(|| {
        format!(
            "failed to scan TLS certificate directory {}",
            config.cert_dir().display()
        )
    })?;

    while let Some(entry) = entries.next_entry().await.with_context(|| {
        format!(
            "failed while scanning TLS certificate directory {}",
            config.cert_dir().display()
        )
    })? {
        let metadata = fs::metadata(entry.path())
            .await
            .with_context(|| format!("failed to inspect TLS path {}", entry.path().display()))?;
        if !metadata.is_file() {
            continue;
        }
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };

        if let Some(id) = file_name.strip_suffix(config.cert_suffix()) {
            if id.is_empty() {
                bail!("TLS certificate filename {file_name:?} has an empty certificate id");
            }
            if certs.insert(id.to_owned(), entry.path()).is_some() {
                bail!("duplicate TLS certificate id {id:?}");
            }
        } else if let Some(id) = file_name.strip_suffix(config.key_suffix()) {
            if id.is_empty() {
                bail!("TLS key filename {file_name:?} has an empty certificate id");
            }
            if keys.insert(id.to_owned(), entry.path()).is_some() {
                bail!("duplicate TLS key id {id:?}");
            }
        }
    }

    let mut ids = certs.keys().cloned().collect::<HashSet<_>>();
    ids.extend(keys.keys().cloned());
    let mut ids = ids.into_iter().collect::<Vec<_>>();
    ids.sort();

    let mut pairs = HashMap::new();
    for id in ids {
        let cert_path = certs
            .remove(&id)
            .ok_or_else(|| anyhow!("TLS private key {id:?} has no matching certificate"))?;
        let key_path = keys
            .remove(&id)
            .ok_or_else(|| anyhow!("TLS certificate {id:?} has no matching private key"))?;
        pairs.insert(id, (cert_path, key_path));
    }
    Ok(pairs)
}

fn parse_certificate_pair(
    id: &str,
    certificate_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<(Arc<CertifiedKey>, CertificateMetadata)> {
    let mut certificate_reader = BufReader::new(certificate_bytes);
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse TLS certificate chain for {id:?}"))?;
    let Some(leaf_certificate) = certificates.first().cloned() else {
        bail!("TLS certificate {id:?} contains no certificates");
    };

    let mut key_reader = BufReader::new(key_bytes);
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("failed to parse TLS private key for {id:?}"))?
        .ok_or_else(|| anyhow!("TLS private key {id:?} contains no supported private key"))?;
    let provider = rustls::crypto::ring::default_provider();
    let certified_key = Arc::new(
        CertifiedKey::from_der(certificates, private_key, &provider).with_context(|| {
            format!("TLS certificate and private key for {id:?} are incompatible")
        })?,
    );
    let metadata = parse_leaf_metadata(id, leaf_certificate)?;
    Ok((certified_key, metadata))
}

fn parse_leaf_metadata(
    id: &str,
    leaf_certificate: CertificateDer<'static>,
) -> Result<CertificateMetadata> {
    let (_, certificate) = X509Certificate::from_der(leaf_certificate.as_ref())
        .map_err(|error| anyhow!("failed to parse leaf X.509 certificate {id:?}: {error}"))?;
    let mut dns_names = Vec::new();
    for extension in certificate.extensions() {
        if let ParsedExtension::SubjectAlternativeName(subject_alt_name) =
            extension.parsed_extension()
        {
            for name in &subject_alt_name.general_names {
                if let GeneralName::DNSName(name) = name {
                    dns_names.push(name.trim_end_matches('.').to_ascii_lowercase());
                }
            }
        }
    }
    dns_names.sort();
    dns_names.dedup();
    if dns_names.is_empty() {
        bail!("TLS certificate {id:?} contains no DNS Subject Alternative Names");
    }
    for name in &dns_names {
        if let Some(suffix) = name.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') {
                bail!("TLS certificate {id:?} contains unsupported wildcard SAN {name:?}");
            }
        } else if name.contains('*') {
            bail!("TLS certificate {id:?} contains unsupported wildcard SAN {name:?}");
        }
    }
    let not_after_unix = certificate.validity().not_after.timestamp();
    drop(certificate);

    Ok(CertificateMetadata {
        dns_names,
        leaf_certificate,
        not_after_unix,
    })
}
