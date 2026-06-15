//! futures-rustls connector trusting the webpki (Mozilla) roots.
#![cfg(feature = "tls")]

/// A rustls client config trusting the webpki (Mozilla) roots — deterministic
/// builds, no platform cert store reads. Callers needing custom CAs supply
/// their own connector through
/// [`ClientOptions::with_tls_connector`](crate::ClientOptions::with_tls_connector).
pub(crate) fn default_tls_connector() -> futures_rustls::TlsConnector {
  let mut roots = rustls::RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
  let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  futures_rustls::TlsConnector::from(std::sync::Arc::new(config))
}
