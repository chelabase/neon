//! `storage_broker::connect` to an https endpoint used to install ring as the process-default
//! crypto provider, racing the binaries' aws-lc-rs install. It must install aws-lc-rs when no
//! provider is installed yet, and leave an installed one alone. Each test is its own process
//! under nextest, so the process-wide default starts unset.

use std::sync::Arc;
use std::time::Duration;

use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;

/// aws-lc-rs (with rustls' `prefer-post-quantum`) offers the hybrid ML-KEM group; ring doesn't.
fn is_aws_lc_rs(provider: &CryptoProvider) -> bool {
    provider
        .kx_groups
        .iter()
        .any(|g| g.name() == NamedGroup::X25519MLKEM768)
}

#[tokio::test]
async fn https_connect_without_a_default_installs_aws_lc_rs() {
    assert!(CryptoProvider::get_default().is_none());
    storage_broker::connect(
        "https://127.0.0.1:9",
        Duration::from_secs(5),
        storage_broker::ClientTlsConfig::new(),
    )
    .expect("lazy connect");
    let current = CryptoProvider::get_default().expect("connect installed a provider");
    assert!(
        is_aws_lc_rs(current),
        "connect must install aws-lc-rs, not ring"
    );
}

#[tokio::test]
async fn https_connect_keeps_the_binarys_provider() {
    http_utils::tls_certs::install_default_crypto_provider();
    let before = Arc::clone(CryptoProvider::get_default().expect("installed"));
    storage_broker::connect(
        "https://127.0.0.1:9",
        Duration::from_secs(5),
        storage_broker::ClientTlsConfig::new(),
    )
    .expect("lazy connect");
    let after = CryptoProvider::get_default().expect("still installed");
    assert!(Arc::ptr_eq(&before, after));
}
