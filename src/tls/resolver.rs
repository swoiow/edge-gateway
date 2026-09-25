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

        resolve_server_name(
            index.exact_certificates(),
            index.wildcard_certificates(),
            index.default_certificate_ref(),
            &server_name,
        )
        .cloned()
    }
}

fn resolve_server_name<'a, T>(
    exact_certificates: &'a HashMap<String, T>,
    wildcard_certificates: &'a HashMap<String, T>,
    default_certificate: Option<&'a T>,
    server_name: &str,
) -> Option<&'a T> {
    exact_certificates
        .get(server_name)
        .or_else(|| resolve_wildcard(wildcard_certificates, server_name))
        .or(default_certificate)
}

fn resolve_wildcard<'a, T>(
    wildcard_certificates: &'a HashMap<String, T>,
    server_name: &str,
) -> Option<&'a T> {
    let (_, suffix) = server_name.split_once('.')?;
    wildcard_certificates.get(suffix)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::resolve_server_name;

    #[test]
    fn exact_certificate_precedes_wildcard_and_default() {
        let exact = HashMap::from([("api.trip2w.com".to_owned(), "exact")]);
        let wildcard = HashMap::from([("trip2w.com".to_owned(), "wildcard")]);

        assert_eq!(
            resolve_server_name(&exact, &wildcard, Some(&"default"), "api.trip2w.com"),
            Some(&"exact")
        );
        assert_eq!(
            resolve_server_name(&exact, &wildcard, Some(&"default"), "www.trip2w.com"),
            Some(&"wildcard")
        );
        assert_eq!(
            resolve_server_name(&exact, &wildcard, Some(&"default"), "unknown.example"),
            Some(&"default")
        );
    }

    #[test]
    fn wildcard_scope_is_single_label() {
        let exact = HashMap::<String, &str>::new();
        let wildcard = HashMap::from([("example.com".to_owned(), "wildcard")]);

        assert_eq!(
            resolve_server_name(&exact, &wildcard, None, "api.example.com"),
            Some(&"wildcard")
        );
        assert_eq!(
            resolve_server_name(&exact, &wildcard, None, "v1.api.example.com"),
            None
        );
    }
}
