//! F3 (fork round 3, final fix round): the TLS watcher's step function, the
//! `pg_ctl reload` exit status, and the TLS feature gate.
//!
//! Pinned interfaces (the code under test):
//! - `compute_tools::tls::CertDigest::of(data: &[u8]) -> CertDigest`: the SHA-256
//!   digest of a certificate file's bytes, as the poller computes it.
//! - `compute_tools::tls::CertWatch::new(loaded: CertDigest) -> CertWatch`: the
//!   watcher's state, starting from the certificate Postgres was started with.
//! - `CertWatch::poll(&mut self, now: CertDigest, reload: impl FnOnce() ->
//!   anyhow::Result<()>) -> CertPoll`: one poll. Runs `reload` (in compute_ctl:
//!   `reload_tls_files(pgdata, tls, || pg_reload_conf())`) when `now` differs from
//!   the last loaded digest or an earlier reload failed; never otherwise.
//! - `compute_tools::tls::CertPoll { Unchanged, Reloaded, Retry }` (Debug,
//!   PartialEq, Eq): nothing to do / reloaded / failed, retried at the next poll
//!   whatever the digest then.
//! - `compute_tools::compute::pg_ctl_reload(pg_ctl: &Path, pgdata: &Path) ->
//!   anyhow::Result<()>`: runs `<pg_ctl> reload -D <pgdata>`; a failure to start
//!   it or a non-zero exit is an error (never a panic). `ComputeNode::pg_reload_conf`
//!   calls it.
//! - `compute_tools::compute::tls_config_for<'a>(features: &[ComputeFeature], tls:
//!   &'a Option<TlsConfig>) -> &'a Option<TlsConfig>`: `tls` with
//!   `ComputeFeature::TlsExperimental`, `None` without. `ComputeNode::tls_config`
//!   and the start of the certificate watcher both go through it.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use compute_api::responses::TlsConfig;
use compute_api::spec::ComputeFeature;
use compute_tools::compute::{pg_ctl_reload, tls_config_for};
use compute_tools::tls::{CertDigest, CertPoll, CertWatch, reload_tls_files};

fn ok() -> anyhow::Result<()> {
    Ok(())
}

#[test]
fn an_unchanged_certificate_reloads_nothing() {
    let mut watch = CertWatch::new(CertDigest::of(b"cert a"));
    let calls = Cell::new(0);
    for _ in 0..3 {
        let poll = watch.poll(CertDigest::of(b"cert a"), || {
            calls.set(calls.get() + 1);
            ok()
        });
        assert_eq!(poll, CertPoll::Unchanged);
    }
    assert_eq!(calls.get(), 0);
}

#[test]
fn a_changed_certificate_reloads_once() {
    let mut watch = CertWatch::new(CertDigest::of(b"cert a"));
    let calls = Cell::new(0);
    let reload = || {
        calls.set(calls.get() + 1);
        ok()
    };
    assert_eq!(
        watch.poll(CertDigest::of(b"cert b"), reload),
        CertPoll::Reloaded
    );
    assert_eq!(
        watch.poll(CertDigest::of(b"cert b"), reload),
        CertPoll::Unchanged
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn a_failed_reload_is_retried_at_the_next_poll() {
    let mut watch = CertWatch::new(CertDigest::of(b"cert a"));
    let calls = Cell::new(0);
    let failing = || {
        calls.set(calls.get() + 1);
        Err(anyhow::anyhow!("pg_ctl reload exited with 1"))
    };
    let working = || {
        calls.set(calls.get() + 1);
        ok()
    };
    assert_eq!(
        watch.poll(CertDigest::of(b"cert b"), failing),
        CertPoll::Retry
    );
    assert_eq!(
        watch.poll(CertDigest::of(b"cert b"), failing),
        CertPoll::Retry,
        "the same digest: retried anyway"
    );
    assert_eq!(
        watch.poll(CertDigest::of(b"cert b"), working),
        CertPoll::Reloaded
    );
    assert_eq!(
        watch.poll(CertDigest::of(b"cert b"), working),
        CertPoll::Unchanged
    );
    assert_eq!(calls.get(), 3);
}

#[test]
fn a_pending_reload_runs_even_when_the_digest_changes_back() {
    // The failed reload may have written the new files before pg_ctl failed:
    // pgdata no longer matches what Postgres serves, so it runs again.
    let mut watch = CertWatch::new(CertDigest::of(b"cert a"));
    let calls = Cell::new(0);
    let poll = watch.poll(CertDigest::of(b"cert b"), || {
        calls.set(calls.get() + 1);
        Err(anyhow::anyhow!("reload failed"))
    });
    assert_eq!(poll, CertPoll::Retry);
    let poll = watch.poll(CertDigest::of(b"cert a"), || {
        calls.set(calls.get() + 1);
        ok()
    });
    assert_eq!(poll, CertPoll::Reloaded);
    assert_eq!(calls.get(), 2);
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

fn self_signed(dir: &Path, name: &str) {
    openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.crt"),
            "-days",
            "2",
            "-subj",
            "/CN=compute",
        ],
    );
}

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("pgdata")).unwrap();
    dir
}

/// A renewal seen with the new certificate but the old key: no reload, nothing
/// written; once the key lands, the same digest reloads at the next poll.
#[test]
fn a_renewal_seen_mid_write_is_retried_with_the_real_files() {
    let dir = fresh("f3_watch_mid_write");
    let pg = dir.join("pgdata");
    self_signed(&dir, "old");
    self_signed(&dir, "new");
    let tls = TlsConfig {
        key_path: dir.join("server.key").to_string_lossy().into(),
        cert_path: dir.join("server.crt").to_string_lossy().into(),
        ca_path: None,
    };
    let new_crt = std::fs::read(dir.join("new.crt")).unwrap();
    std::fs::copy(dir.join("old.key"), dir.join("server.key")).unwrap();
    std::fs::copy(dir.join("new.crt"), dir.join("server.crt")).unwrap();
    let old_digest = CertDigest::of(&std::fs::read(dir.join("old.crt")).unwrap());

    let mut watch = CertWatch::new(old_digest);
    let pg_reloads = Cell::new(0);
    let pg_reload = || {
        pg_reloads.set(pg_reloads.get() + 1);
        ok()
    };
    let poll = watch.poll(CertDigest::of(&new_crt), || {
        reload_tls_files(&pg, &tls, pg_reload)
    });
    assert_eq!(poll, CertPoll::Retry);
    assert_eq!(pg_reloads.get(), 0);
    assert!(!pg.join("server.crt").exists());

    std::fs::copy(dir.join("new.key"), dir.join("server.key")).unwrap();
    let poll = watch.poll(CertDigest::of(&new_crt), || {
        reload_tls_files(&pg, &tls, pg_reload)
    });
    assert_eq!(poll, CertPoll::Reloaded);
    assert_eq!(pg_reloads.get(), 1);
    assert_eq!(std::fs::read(pg.join("server.crt")).unwrap(), new_crt);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn pg_ctl_failures_are_errors() {
    let pgdata = Path::new("./tests/tmp/f3_pg_ctl");
    assert!(
        pg_ctl_reload(Path::new("/bin/false"), pgdata).is_err(),
        "a non-zero exit is an error"
    );
    assert!(
        pg_ctl_reload(Path::new("./tests/tmp/f3_no_such_pg_ctl"), pgdata).is_err(),
        "a pg_ctl that can't start is an error, not a panic"
    );
    pg_ctl_reload(Path::new("/bin/true"), pgdata).unwrap();
}

#[test]
fn the_tls_watcher_follows_the_tls_experimental_feature() {
    let tls = Some(TlsConfig {
        key_path: "/var/db/chelabase/tls/server.key".into(),
        cert_path: "/var/db/chelabase/tls/server.crt".into(),
        ca_path: Some("/var/db/chelabase/tls/ca.crt".into()),
    });
    assert_eq!(tls_config_for(&[], &tls), &None);
    assert_eq!(
        tls_config_for(&[ComputeFeature::TlsExperimental], &tls),
        &tls
    );
    assert_eq!(
        tls_config_for(&[ComputeFeature::TlsExperimental], &None),
        &None
    );
}
