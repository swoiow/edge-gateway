use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use super::store::CertificateIndex;

pub(super) struct DynamicCertResolver {
    index: Arc<ArcSwap<CertificateIndex>>,
}

impl DynamicCertResolver {
    pub(super) fn new(index: Arc<ArcSwap<CertificateIndex>>) -> Self {
        Self { index }
    }
}

impl fmt::Debug for DynamicCertResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DynamicCertResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let index = self.index.load();
        let Some(server_name) = client_hello.server_name() else {
            return index.default_certificate();
        };
        let server_name = server_name.trim_end_matches('.').to_ascii_lowercase();

        index
            .exact_certificate(&server_name)
            .or_else(|| resolve_wildcard(index.wildcard_certificates(), &server_name))
            .or_else(|| index.default_certificate())
    }
}

fn resolve_wildcard(
    wildcard_certificates: &HashMap<String, Arc<CertifiedKey>>,
    server_name: &str,
) -> Option<Arc<CertifiedKey>> {
    let (_, suffix) = server_name.split_once('.')?;
    wildcard_certificates.get(suffix).cloned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn wildcard_scope_is_single_label() {
        assert_eq!(
            "api.example.com".split_once('.').map(|(_, suffix)| suffix),
            Some("example.com")
        );
        assert_eq!(
            "v1.api.example.com".split_once('.').map(|(_, suffix)| suffix),
            Some("api.example.com")
        );
    }
}
