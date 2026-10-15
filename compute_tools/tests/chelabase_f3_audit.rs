//! F3 audit findings (fork round 3, final fix round) that today's interfaces can
//! express: a panicking reload step (2), certificate validity dates in the chain
//! check (4), P-256 ECDSA only and no `ring` in the TLS code (6), and the
//! structural halves of 1 (reconfigure writes its files all-or-nothing through
//! `config::rewrite_config_files`) and 3 (the watcher digests key, certificate
//! and CA through `tls::read_tls_digest` / `tls::wait_for_tls`). The new
//! interfaces themselves are tested in `chelabase_f3_audit_api.rs`.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use compute_api::responses::TlsConfig;
use compute_tools::tls::{
    CertDigest, CertPoll, CertWatch, reload_tls_files, verify_cert_chains_to_ca,
};

const COMPUTE_RS: &str = include_str!("../src/compute.rs");
const TLS_RS: &str = include_str!("../src/tls.rs");

/// The text of `fn <name>` in compute.rs, up to the next `fn ` at the same
/// indentation.
fn compute_fn(name: &str) -> &'static str {
    let start = COMPUTE_RS
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} in compute.rs"));
    let rest = &COMPUTE_RS[start + 3..];
    let end = rest
        .find("\n    pub fn ")
        .into_iter()
        .chain(rest.find("\n    fn "))
        .chain(rest.find("\n    pub async fn "))
        .min()
        .unwrap_or(rest.len());
    &COMPUTE_RS[start..start + 3 + end]
}

// ---------------------------------------------------------------------------
// 2: a panic in the reload step is a failed reload, retried at the next poll;
// the watcher never stops for it.
// ---------------------------------------------------------------------------

#[test]
fn a_panicking_reload_is_retried_at_the_next_poll() {
    let mut watch = CertWatch::new(CertDigest::of(b"cert a"));
    let poll = watch.poll(CertDigest::of(b"cert b"), || panic!("reload panicked"));
    assert_eq!(poll, CertPoll::Retry);
    let calls = Cell::new(0);
    let poll = watch.poll(CertDigest::of(b"cert b"), || {
        calls.set(calls.get() + 1);
        Ok(())
    });
    assert_eq!(poll, CertPoll::Reloaded);
    assert_eq!(calls.get(), 1);
}

#[test]
fn the_watcher_loop_only_ends_when_the_compute_terminates() {
    let body = compute_fn("watch_cert_for_changes");
    assert_eq!(
        body.matches("break").count(),
        1,
        "the only `break` is the termination arm:\n{body}"
    );
}

// ---------------------------------------------------------------------------
// 1 and 3, structural halves.
// ---------------------------------------------------------------------------

#[test]
fn reconfigure_writes_its_files_all_or_nothing() {
    let body = compute_fn("reconfigure");
    assert!(body.contains("rewrite_config_files("), "{body}");
    for direct in ["write_postgres_conf(", "update_pg_hba(", "update_pg_ident("] {
        assert!(
            !body.contains(direct),
            "reconfigure calls {direct} directly"
        );
    }
}

#[test]
fn the_watcher_digests_key_certificate_and_ca() {
    let body = compute_fn("watch_cert_for_changes");
    assert!(body.contains("wait_for_tls("), "{body}");
    assert!(body.contains("read_tls_digest("), "{body}");
    assert!(!body.contains("read_cert_digest(") && !body.contains("wait_for_cert("));
}

// ---------------------------------------------------------------------------
// 4 and 6: the chain check.
// ---------------------------------------------------------------------------

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("pgdata")).unwrap();
    dir
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// A self-signed CA `<name>.crt`/`<name>.key` with the given `-newkey` arguments.
fn make_ca(dir: &Path, name: &str, newkey: &[&str]) {
    let key = format!("{name}.key");
    let crt = format!("{name}.crt");
    let mut args = vec!["req", "-x509"];
    args.extend_from_slice(newkey);
    args.extend_from_slice(&[
        "-nodes", "-keyout", &key, "-out", &crt, "-days", "2", "-sha256", "-subj", "/CN=ca",
    ]);
    openssl(dir, &args);
}

const P256: &[&str] = &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"];

/// A P-256 server key `<name>.key` and request `<name>.csr`.
fn make_csr(dir: &Path, name: &str) {
    let key = format!("{name}.key");
    let csr = format!("{name}.csr");
    let mut args = vec!["req"];
    args.extend_from_slice(P256);
    args.extend_from_slice(&[
        "-nodes",
        "-keyout",
        &key,
        "-out",
        &csr,
        "-subj",
        "/CN=compute",
    ]);
    openssl(dir, &args);
}

/// Signs `<name>.csr` with CA `ca` into `<name>.crt`, valid from `start` to
/// `end` (YYYYMMDDHHMMSSZ), through `openssl ca` (OpenSSL 3.0's `x509` can't set
/// past or future dates).
fn sign_dated(dir: &Path, name: &str, ca: &str, start: &str, end: &str) {
    std::fs::write(
        dir.join("ca.cnf"),
        "[ ca ]\ndefault_ca = d\n[ d ]\ndatabase = index.txt\nnew_certs_dir = .\n\
         serial = serial\ndefault_md = sha256\npolicy = any\nunique_subject = no\n\
         [ any ]\ncommonName = supplied\n",
    )
    .unwrap();
    if !dir.join("index.txt").exists() {
        std::fs::write(dir.join("index.txt"), "").unwrap();
        std::fs::write(dir.join("serial"), "1000\n").unwrap();
    }
    openssl(
        dir,
        &[
            "ca",
            "-batch",
            "-notext",
            "-config",
            "ca.cnf",
            "-cert",
            &format!("{ca}.crt"),
            "-keyfile",
            &format!("{ca}.key"),
            "-in",
            &format!("{name}.csr"),
            "-out",
            &format!("{name}.crt"),
            "-startdate",
            start,
            "-enddate",
            end,
        ],
    );
}

/// Signs `<name>.csr` with CA `ca` for two days from now.
fn sign(dir: &Path, name: &str, ca: &str) {
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{ca}.crt"),
            "-CAkey",
            &format!("{ca}.key"),
            "-CAcreateserial",
            "-days",
            "2",
            "-sha256",
            "-out",
            &format!("{name}.crt"),
        ],
    );
}

/// 4: an expired or not yet valid server certificate isn't loaded.
#[test]
fn the_chain_check_refuses_a_certificate_outside_its_dates() {
    let dir = fresh("f3_audit_dates");
    make_ca(&dir, "ca", P256);
    let ca = read(&dir.join("ca.crt"));
    for name in ["ok", "expired", "future"] {
        make_csr(&dir, name);
    }
    sign_dated(&dir, "ok", "ca", "20200101000000Z", "20991231000000Z");
    sign_dated(&dir, "expired", "ca", "20200101000000Z", "20200102000000Z");
    sign_dated(&dir, "future", "ca", "20990101000000Z", "20991231000000Z");
    verify_cert_chains_to_ca(&read(&dir.join("ok.crt")), &ca).unwrap();

    for name in ["expired", "future"] {
        assert!(
            verify_cert_chains_to_ca(&read(&dir.join(format!("{name}.crt"))), &ca).is_err(),
            "{name}"
        );
        std::fs::copy(dir.join(format!("{name}.key")), dir.join("server.key")).unwrap();
        std::fs::copy(dir.join(format!("{name}.crt")), dir.join("server.crt")).unwrap();
        let tls = TlsConfig {
            key_path: dir.join("server.key").to_string_lossy().into(),
            cert_path: dir.join("server.crt").to_string_lossy().into(),
            ca_path: Some(dir.join("ca.crt").to_string_lossy().into()),
        };
        let reloads = Cell::new(0);
        let result = reload_tls_files(&dir.join("pgdata"), &tls, || {
            reloads.set(reloads.get() + 1);
            Ok(())
        });
        assert!(result.is_err(), "{name}: not loaded");
        assert_eq!(reloads.get(), 0, "{name}");
        assert!(!dir.join("pgdata/server.crt").exists(), "{name}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 6: the chain check accepts P-256 ECDSA (SHA-256) and refuses other CAs.
#[test]
fn the_chain_check_accepts_only_p256_ecdsa() {
    let dir = fresh("f3_audit_algorithms");
    make_ca(&dir, "p256", P256);
    make_ca(
        &dir,
        "p384",
        &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
    );
    make_ca(&dir, "rsa", &["-newkey", "rsa:2048"]);
    for ca in ["p256", "p384", "rsa"] {
        let name = format!("by_{ca}");
        make_csr(&dir, &name);
        sign(&dir, &name, ca);
    }
    let check = |ca: &str| {
        verify_cert_chains_to_ca(
            &read(&dir.join(format!("by_{ca}.crt"))),
            &read(&dir.join(format!("{ca}.crt"))),
        )
    };
    check("p256").unwrap();
    assert!(check("p384").is_err(), "a P-384 CA");
    assert!(check("rsa").is_err(), "an RSA CA");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 6: product rule, aws-lc-rs over ring.
#[test]
fn the_tls_code_does_not_use_ring() {
    for needle in ["ring::", "use ring"] {
        assert!(!TLS_RS.contains(needle), "tls.rs uses {needle}");
    }
}
