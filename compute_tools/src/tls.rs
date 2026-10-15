use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use aws_lc_rs::digest;
use compute_api::responses::TlsConfig;
use x509_cert::Certificate;

/// A SHA-256 digest of the TLS files' bytes.
#[derive(Clone, Copy)]
pub struct CertDigest(digest::Digest);

impl CertDigest {
    pub fn of(data: &[u8]) -> CertDigest {
        // sha256 is extremely collision resistent. can safely assume the digest to be unique
        CertDigest(digest::digest(&digest::SHA256, data))
    }
}

impl PartialEq for CertDigest {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for CertDigest {}

impl std::fmt::Debug for CertDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertDigest(")?;
        for b in self.0.as_ref() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// The outcome of one [`CertWatch::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertPoll {
    /// The certificate is the one loaded and no reload is pending.
    Unchanged,
    /// The reload ran and succeeded.
    Reloaded,
    /// The reload failed; it runs again at the next poll, whatever the digest then.
    Retry,
}

/// The certificate watcher's state (RT3-1, T6 m5): the digest Postgres was last
/// loaded with, and whether a reload is pending after a failure.
#[derive(Debug)]
pub struct CertWatch {
    loaded: CertDigest,
    pending: bool,
}

impl CertWatch {
    /// Starts from the certificate Postgres was started with.
    pub fn new(loaded: CertDigest) -> CertWatch {
        CertWatch {
            loaded,
            pending: false,
        }
    }

    /// One poll: runs `reload` when `now` differs from the loaded digest or an
    /// earlier reload failed (it may have written files before failing, so pgdata
    /// no longer matches what Postgres serves); never otherwise. A `reload` that
    /// panics counts as a failed one: retried at the next poll.
    pub fn poll(&mut self, now: CertDigest, reload: impl FnOnce() -> Result<()>) -> CertPoll {
        if !self.pending && now == self.loaded {
            return CertPoll::Unchanged;
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(reload))
            .unwrap_or_else(|panic| Err(panicked(&*panic)));
        match result {
            Ok(()) => {
                self.loaded = now;
                self.pending = false;
                CertPoll::Reloaded
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "could not reload the changed TLS certificate, retrying at the next poll"
                );
                self.pending = true;
                CertPoll::Retry
            }
        }
    }
}

/// The error for a reload that panicked, with the panic's message.
fn panicked(panic: &(dyn std::any::Any + Send)) -> anyhow::Error {
    let what = panic
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    anyhow::anyhow!("the reload panicked: {what}")
}

/// One digest of the key, the certificate and (with `ca_path`) the CA file,
/// each prefixed by its length, so a change to any of them (a CA-only rotation
/// included) changes it. An unreadable file is an error.
pub fn read_tls_digest(tls: &TlsConfig) -> Result<CertDigest> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    let paths = [
        Some(&tls.key_path),
        Some(&tls.cert_path),
        tls.ca_path.as_ref(),
    ];
    for path in paths.into_iter().flatten() {
        let data = std::fs::read(path).with_context(|| format!("read {path}"))?;
        ctx.update(&(data.len() as u64).to_be_bytes());
        ctx.update(&data);
    }
    Ok(CertDigest(ctx.finish()))
}

/// Waits until [`read_tls_digest`] succeeds and returns its digest.
pub async fn wait_for_tls(tls: &TlsConfig) -> CertDigest {
    loop {
        match read_tls_digest(tls) {
            Ok(digest) => break digest,
            Err(e) => {
                tracing::error!(error = ?e, "could not read the TLS files");
                tokio::time::sleep(Duration::from_secs(1)).await
            }
        }
    }
}

pub const SERVER_CRT: &str = "server.crt";
pub const SERVER_KEY: &str = "server.key";

pub fn update_key_path_blocking(pg_data: &Path, tls_config: &TlsConfig) {
    loop {
        match try_update_key_path_blocking(pg_data, tls_config) {
            Ok(()) => break,
            Err(e) => {
                tracing::error!(error = ?e, "could not create key file");
                std::thread::sleep(Duration::from_secs(1))
            }
        }
    }
}

/// A changed certificate (RT3-1): copy the key and certificate into `pgdata` and
/// run `reload` (Postgres reloads its TLS files on SIGHUP). The compute's status
/// is never touched. Fails, writing nothing and reloading nothing, while the key
/// doesn't match the certificate or (with `ca_path`) the certificate doesn't chain
/// to the CA file (a renewal or CA rotation seen half-written): the caller
/// retries at its next poll.
pub fn reload_tls_files(
    pgdata: &Path,
    tls: &TlsConfig,
    reload: impl FnOnce() -> Result<()>,
) -> Result<()> {
    try_update_key_path_blocking(pgdata, tls)
        .context("copy the TLS key and certificate into pgdata")?;
    reload().context("reload Postgres")
}

/// One attempt at copying the key and certificate into `pgdata` (checked as
/// [`reload_tls_files`] checks them); nothing is written on failure.
pub(crate) fn copy_tls_files(pgdata: &Path, tls: &TlsConfig) -> Result<()> {
    try_update_key_path_blocking(pgdata, tls)
}

/// Serialises copies into pgdata within this process (the certificate watcher
/// and a reconfigure), so the key and certificate written are always one pair.
static COPY_LOCK: Mutex<()> = Mutex::new(());

// Postgres requires the keypath be "secure". This means
// 1. Owned by the postgres user.
// 2. Have permission 600.
fn try_update_key_path_blocking(pg_data: &Path, tls_config: &TlsConfig) -> Result<()> {
    let _guard = COPY_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let key = std::fs::read_to_string(&tls_config.key_path)
        .with_context(|| format!("read {}", tls_config.key_path))?;
    let crt = std::fs::read_to_string(&tls_config.cert_path)
        .with_context(|| format!("read {}", tls_config.cert_path))?;

    // to mitigate a race condition during renewal.
    verify_key_cert(&key, &crt)?;
    if let Some(ca_path) = &tls_config.ca_path {
        let ca = std::fs::read_to_string(ca_path).with_context(|| format!("read {ca_path}"))?;
        verify_cert_chains_to_ca(&crt, &ca)
            .with_context(|| format!("{} doesn't chain to {ca_path}", tls_config.cert_path))?;
    }

    // Each file is replaced by a rename, so Postgres never reads a truncated one,
    // and always ends up 0600 whatever an older copy's mode was.
    write_private_file(pg_data, SERVER_KEY, key.as_bytes())?;
    write_private_file(pg_data, SERVER_CRT, crt.as_bytes())?;

    Ok(())
}

/// Distinguishes temporary files written at the same time in this process.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn write_private_file(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    // A unique name per write: two writers (in this process or another) never
    // share a temporary file.
    let tmp = dir.join(format!(
        "{name}.tmp.{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, dir.join(name))
            .with_context(|| format!("rename {} into place", tmp.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The longest issuer chain followed from the server certificate to the CA file.
const MAX_CHAIN_DEPTH: usize = 8;

/// Checks that the first certificate in `cert` (the server's, followed by any
/// intermediates) chains to a certificate in the PEM bundle `ca`: each link's
/// issuer names the next certificate's subject and its signature verifies with
/// that certificate's key. Only P-256 ECDSA (SHA-256) is accepted, as for keys.
/// The server certificate must be valid now (not expired, not yet to come).
pub fn verify_cert_chains_to_ca(cert: &str, ca: &str) -> Result<()> {
    let chain = Certificate::load_pem_chain(cert.as_bytes())
        .context("decoding PEM encoded certificates")?;
    let cas =
        Certificate::load_pem_chain(ca.as_bytes()).context("decoding the PEM encoded CA file")?;
    let Some(mut current) = chain.first() else {
        bail!("no certificates found");
    };
    let validity = &current.tbs_certificate.validity;
    let now = std::time::SystemTime::now();
    if now < validity.not_before.to_system_time() {
        bail!(
            "the certificate isn't valid yet (not before {:?})",
            validity.not_before
        );
    }
    if now > validity.not_after.to_system_time() {
        bail!(
            "the certificate has expired (not after {:?})",
            validity.not_after
        );
    }
    if cas.is_empty() {
        bail!("no CA certificates found");
    }
    let intermediates = &chain[1..];
    for _ in 0..MAX_CHAIN_DEPTH {
        let issued_by = |c: &&Certificate| {
            c.tbs_certificate.subject == current.tbs_certificate.issuer
                && signed_by(current, c).is_ok()
        };
        if cas.iter().any(|c| issued_by(&c)) {
            return Ok(());
        }
        match intermediates.iter().find(issued_by) {
            Some(next) => current = next,
            None => break,
        }
    }
    bail!("the certificate isn't signed by any certificate in the CA file")
}

/// Verifies `cert`'s signature with `issuer`'s public key.
fn signed_by(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    use x509_cert::der::Encode;
    use x509_cert::der::oid::db::rfc5912::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, SECP_256_R_1};

    if cert.signature_algorithm.oid != ECDSA_WITH_SHA_256 {
        bail!("unsupported certificate signature algorithm");
    }
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<x509_cert::der::oid::ObjectIdentifier>().ok());
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY || curve != Some(SECP_256_R_1) {
        bail!("unsupported CA key type");
    }
    let tbs = cert
        .tbs_certificate
        .to_der()
        .context("encode the certificate")?;
    let signature = cert
        .signature
        .as_bytes()
        .context("the certificate signature isn't a whole number of bytes")?;
    let key = spki
        .subject_public_key
        .as_bytes()
        .context("the CA key isn't a whole number of bytes")?;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
        .verify(&tbs, signature)
        .map_err(|_| anyhow::anyhow!("signature mismatch"))
}

/// Checks that `key` (PEM: PKCS#8 `PRIVATE KEY` or SEC1 `EC PRIVATE KEY`, P-256)
/// is the private key of the first certificate in `cert`.
pub fn verify_key_cert(key: &str, cert: &str) -> Result<()> {
    use x509_cert::der::oid::db::rfc5912::ECDSA_WITH_SHA_256;

    let certs = Certificate::load_pem_chain(cert.as_bytes())
        .context("decoding PEM encoded certificates")?;

    // First certificate is our server-cert,
    // all the rest of the certs are the CA cert chain.
    let Some(cert) = certs.first() else {
        bail!("no certificates found");
    };

    match cert.signature_algorithm.oid {
        ECDSA_WITH_SHA_256 => {
            let key = if key.contains("-----BEGIN PRIVATE KEY-----") {
                use p256::pkcs8::DecodePrivateKey;
                p256::SecretKey::from_pkcs8_pem(key.trim()).context("parse PKCS#8 key")?
            } else {
                p256::SecretKey::from_sec1_pem(key).context("parse key")?
            };

            let a = key.public_key().to_sec1_bytes();
            let b = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();

            if *a != *b {
                bail!("private key file does not match certificate")
            }
        }
        _ => bail!("unknown TLS key type"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verify_key_cert;

    /// Real certificate chain file, generated by cert-manager in dev.
    /// The server auth certificate has expired since 2025-04-24T15:41:35Z.
    const CERT: &str = "
-----BEGIN CERTIFICATE-----
MIICCDCCAa+gAwIBAgIQKhLomFcNULbZA/bPdGzaSzAKBggqhkjOPQQDAjBEMQsw
CQYDVQQGEwJVUzESMBAGA1UEChMJTmVvbiBJbmMuMSEwHwYDVQQDExhOZW9uIEs4
cyBJbnRlcm1lZGlhdGUgQ0EwHhcNMjUwNDIzMTU0MTM1WhcNMjUwNDI0MTU0MTM1
WjBBMT8wPQYDVQQDEzZjb21wdXRlLXdpc3B5LWdyYXNzLXcwY21laWp3LmRlZmF1
bHQuc3ZjLmNsdXN0ZXIubG9jYWwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATF
QCcG2m/EVHAiZtSsYgVnHgoTjUL/Jtwfdrpvz2t0bVRZmBmSKhlo53uPV9Y5eKFG
AmR54p9/gT2eO3xU7vAgo4GFMIGCMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8E
AjAAMB8GA1UdIwQYMBaAFFR2JAhXkeiNQNEixTvAYIwxUu3QMEEGA1UdEQQ6MDiC
NmNvbXB1dGUtd2lzcHktZ3Jhc3MtdzBjbWVpancuZGVmYXVsdC5zdmMuY2x1c3Rl
ci5sb2NhbDAKBggqhkjOPQQDAgNHADBEAiBLG22wKG8XS9e9RxBT+kmUx/kIThcP
DIpp7jx0PrFcdQIgEMTdnXpx5Cv/Z0NIEDxtMHUD7G0vuRPfztki36JuakM=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICFzCCAb6gAwIBAgIUbbX98N2Ip6lWAONRk8dU9hSz+YIwCgYIKoZIzj0EAwIw
RDELMAkGA1UEBhMCVVMxEjAQBgNVBAoTCU5lb24gSW5jLjEhMB8GA1UEAxMYTmVv
biBBV1MgSW50ZXJtZWRpYXRlIENBMB4XDTI1MDQyMjE1MTAxMFoXDTI1MDcyMTE1
MTAxMFowRDELMAkGA1UEBhMCVVMxEjAQBgNVBAoTCU5lb24gSW5jLjEhMB8GA1UE
AxMYTmVvbiBLOHMgSW50ZXJtZWRpYXRlIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE5++m5owqNI4BPMTVNIUQH0qvU7pYhdpHGVGhdj/Lgars6ROvE6uSNQV4
SAmJN5HBzj5/6kLQaTPWpXW7EHXjK6OBjTCBijAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUVHYkCFeR6I1A0SLFO8BgjDFS7dAw
HwYDVR0jBBgwFoAUgHfNXfyKtHO0V9qoLOWCjkNiaI8wJAYDVR0eAQH/BBowGKAW
MBSCEi5zdmMuY2x1c3Rlci5sb2NhbDAKBggqhkjOPQQDAgNHADBEAiBObVFFdXaL
QpOXmN60dYUNnQRwjKreFduEkQgOdOlssgIgVAdJJQFgvlrvEOBhY8j5WyeKRwUN
k/ALs6KpgaFBCGY=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB4jCCAYegAwIBAgIUFlxWFn/11yoGdmD+6gf+yQMToS0wCgYIKoZIzj0EAwIw
ODELMAkGA1UEBhMCVVMxEjAQBgNVBAoTCU5lb24gSW5jLjEVMBMGA1UEAxMMTmVv
biBSb290IENBMB4XDTI1MDQwMzA3MTUyMloXDTI2MDQwMzA3MTUyMlowRDELMAkG
A1UEBhMCVVMxEjAQBgNVBAoTCU5lb24gSW5jLjEhMB8GA1UEAxMYTmVvbiBBV1Mg
SW50ZXJtZWRpYXRlIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqonG/IQ6
ZxtEtOUTkkoNopPieXDO5CBKUkNFTGeJEB7OxRlSpYJgsBpaYIaD6Vc4sVk3thIF
p+pLw52idQOIN6NjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFIB3zV38irRztFfaqCzlgo5DYmiPMB8GA1UdIwQYMBaAFKh7M4/G
FHvr/ORDQZt4bMLlJvHCMAoGCCqGSM49BAMCA0kAMEYCIQCbS4x7QPslONzBYbjC
UQaQ0QLDW4CJHvQ4u4gbWFG87wIhAJMsHQHjP9qTT27Q65zQCR7O8QeLAfha1jrH
Ag/LsxSr
-----END CERTIFICATE-----
";

    /// The key corresponding to [`CERT`]
    const KEY: &str = "
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDnAnrqmIJjndCLWP1iIO5X3X63Aia48TGpGuMXwvm6IoAoGCCqGSM49
AwEHoUQDQgAExUAnBtpvxFRwImbUrGIFZx4KE41C/ybcH3a6b89rdG1UWZgZkioZ
aOd7j1fWOXihRgJkeeKff4E9njt8VO7wIA==
-----END EC PRIVATE KEY-----
";

    /// An incorrect key.
    const INCORRECT_KEY: &str = "
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIL6WqqBDyvM0HWz7Ir5M5+jhFWB7IzOClGn26OPrzHCXoAoGCCqGSM49
AwEHoUQDQgAE7XVvdOy5lfwtNKb+gJEUtnG+DrnnXLY5LsHDeGQKV9PTRcEMeCrG
YZzHyML4P6Sr4yi2ts+4B9i47uvAG8+XwQ==
-----END EC PRIVATE KEY-----
";

    #[test]
    fn certificate_verification() {
        verify_key_cert(KEY, CERT).unwrap();
    }

    #[test]
    #[should_panic(expected = "private key file does not match certificate")]
    fn certificate_verification_fail() {
        verify_key_cert(INCORRECT_KEY, CERT).unwrap();
    }
}
