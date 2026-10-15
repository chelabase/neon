//! Startup order check: with ring and aws-lc-rs both compiled in, rustls has no implicit process
//! default, so this binary must call `http_utils::tls_certs::install_default_crypto_provider()`
//! before it builds any TLS config through `ServerConfig::builder()`.
//! (The behaviour of the helper is tested in `libs/http-utils/tests/crypto_provider.rs`; this
//! test pins the call site, since the binary's `main` can't be run from a unit test.)

const SRC: &str = include_str!("../src/bin/safekeeper.rs");

#[test]
fn installs_crypto_provider_before_building_tls_configs() {
    let install = SRC
        .find("install_default_crypto_provider()")
        .expect("safekeeper never calls install_default_crypto_provider()");
    let first_builder = SRC
        .find("ServerConfig::builder()")
        .expect("safekeeper builds a ServerConfig through ServerConfig::builder()");
    assert!(
        install < first_builder,
        "install_default_crypto_provider() (byte {install}) must come before the first \
         ServerConfig::builder() (byte {first_builder})"
    );
}
