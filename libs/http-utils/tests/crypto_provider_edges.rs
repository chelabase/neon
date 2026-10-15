//! Edge cases of `http_utils::tls_certs::install_default_crypto_provider()` beyond the basic
//! install tests in `crypto_provider.rs`. Each test is its own process under nextest, so the
//! process-wide default starts unset.

use std::sync::{Arc, Barrier};

use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;

/// aws-lc-rs (with rustls' `prefer-post-quantum`) offers the hybrid ML-KEM group; ring doesn't.
fn is_aws_lc_rs(provider: &CryptoProvider) -> bool {
    provider
        .kx_groups
        .iter()
        .any(|g| g.name() == NamedGroup::X25519MLKEM768)
}

#[test]
fn the_installed_default_is_aws_lc_rs() {
    assert!(!is_aws_lc_rs(&rustls::crypto::ring::default_provider()));

    http_utils::tls_certs::install_default_crypto_provider();

    let current = CryptoProvider::get_default().expect("installed");
    assert!(
        is_aws_lc_rs(current),
        "the process default must be aws-lc-rs, got kx groups {:?}",
        current
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect::<Vec<_>>()
    );
}

#[test]
fn concurrent_installs_neither_panic_nor_disagree() {
    const THREADS: usize = 16;
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                http_utils::tls_certs::install_default_crypto_provider();
                Arc::clone(CryptoProvider::get_default().expect("installed"))
            })
        })
        .collect();
    let providers: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("no install panics"))
        .collect();

    assert!(providers.iter().all(|p| Arc::ptr_eq(p, &providers[0])));
    assert!(is_aws_lc_rs(&providers[0]));
}
