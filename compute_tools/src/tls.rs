use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use compute_api::responses::TlsConfig;
use ring::digest;
use x509_cert::Certificate;

#[derive(Clone, Copy)]
pub struct CertDigest(digest::Digest);

pub async fn watch_cert_for_changes(cert_path: String) -> tokio::sync::watch::Receiver<CertDigest> {
    let mut digest = compute_digest(&cert_path).await;
    let (tx, rx) = tokio::sync::watch::channel(digest);
    tokio::spawn(async move {
        while !tx.is_closed() {
            let new_digest = compute_digest(&cert_path).await;
            if digest.0.as_ref() != new_digest.0.as_ref() {
                digest = new_digest;
                _ = tx.send(digest);
            }

            tokio::time::sleep(Duration::from_secs(60)).await
        }
    });
    rx
}

async fn compute_digest(cert_path: &str) -> CertDigest {
    loop {
        match try_compute_digest(cert_path).await {
            Ok(d) => break d,
            Err(e) => {
                tracing::error!("could not read cert file {e:?}");
                tokio::time::sleep(Duration::from_secs(1)).await
            }
        }
    }
}

async fn try_compute_digest(cert_path: &str) -> Result<CertDigest> {
    let data = tokio::fs::read(cert_path).await?;
    // sha256 is extremely collision resistent. can safely assume the digest to be unique
    Ok(CertDigest(digest::digest(&digest::SHA256, &data)))
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
/// is never touched. Fails, writing nothing, while the key doesn't match the
/// certificate (a renewal seen half-written): the caller retries at its next poll.
pub fn reload_tls_files(
    pgdata: &Path,
    tls: &TlsConfig,
    reload: impl FnOnce() -> Result<()>,
) -> Result<()> {
    try_update_key_path_blocking(pgdata, tls)
        .context("copy the TLS key and certificate into pgdata")?;
    reload().context("reload Postgres")
}

// Postgres requires the keypath be "secure". This means
// 1. Owned by the postgres user.
// 2. Have permission 600.
fn try_update_key_path_blocking(pg_data: &Path, tls_config: &TlsConfig) -> Result<()> {
    let key = std::fs::read_to_string(&tls_config.key_path)
        .with_context(|| format!("read {}", tls_config.key_path))?;
    let crt = std::fs::read_to_string(&tls_config.cert_path)
        .with_context(|| format!("read {}", tls_config.cert_path))?;

    // to mitigate a race condition during renewal.
    verify_key_cert(&key, &crt)?;

    // Each file is replaced by a rename, so Postgres never reads a truncated one,
    // and always ends up 0600 whatever an older copy's mode was.
    write_private_file(pg_data, SERVER_KEY, key.as_bytes())?;
    write_private_file(pg_data, SERVER_CRT, crt.as_bytes())?;

    Ok(())
}

fn write_private_file(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("remove {}", tmp.display())),
    }
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
        .with_context(|| format!("rename {} into place", tmp.display()))?;
    Ok(())
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
