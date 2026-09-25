mod resolver;
mod store;

use std::sync::Arc;

use rustls::ServerConfig as RustlsServerConfig;
pub(crate) use store::{CertificateMetadata, CertificateStore};
use tokio_rustls::TlsAcceptor;

pub(crate) fn build_acceptor(store: &CertificateStore) -> TlsAcceptor {
    let mut tls_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(store.resolver());
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(tls_config))
}
