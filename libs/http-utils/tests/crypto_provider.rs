//! `http_utils::tls_certs::install_default_crypto_provider()` makes rustls' provider-less
//! builders usable. With ring (our own deps) and aws-lc-rs (the AWS SDK) both compiled in, rustls
//! 0.23 cannot pick a process default by itself and `ServerConfig::builder()` /
//! `ClientConfig::builder()` panic, so every binary installs one at start.
//!
//! Each test is its own process under nextest, so the process-wide default starts unset.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

#[test]
fn install_makes_server_and_client_builders_work() {
    http_utils::tls_certs::install_default_crypto_provider();

    assert!(CryptoProvider::get_default().is_some());

    // These panic when two providers are compiled in and no default is installed.
    let _server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
    let _client = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
}

#[test]
fn installing_twice_is_fine_and_keeps_the_first_provider() {
    http_utils::tls_certs::install_default_crypto_provider();
    let first = CryptoProvider::get_default().expect("installed").clone();

    // A second call (another startup path, a test harness) neither panics nor swaps the provider.
    http_utils::tls_certs::install_default_crypto_provider();
    let second = CryptoProvider::get_default()
        .expect("still installed")
        .clone();

    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn install_after_someone_else_installed_a_provider_does_not_panic() {
    // An embedder (or storage_broker's client path) may have installed a provider already; the
    // helper must accept that and leave it alone.
    let theirs = Arc::new(rustls::crypto::ring::default_provider());
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("first install in this process");
    http_utils::tls_certs::install_default_crypto_provider();

    let current = CryptoProvider::get_default().expect("installed");
    assert_eq!(
        current.cipher_suites.len(),
        theirs.cipher_suites.len(),
        "the provider installed first stays the default"
    );
    let _server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
}
