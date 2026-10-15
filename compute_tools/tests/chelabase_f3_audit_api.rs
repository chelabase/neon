//! F3 audit findings 1 and 3: new interfaces.
//!
//! Pinned interfaces (the code under test):
//! - `compute_tools::config::rewrite_config_files(pgdata_path: &Path, params:
//!   &ComputeNodeParams, spec: &ComputeSpec, postgres_port: Option<u16>,
//!   extension_server_port: u16, tls_config: &Option<TlsConfig>, lakebase_mode:
//!   bool) -> anyhow::Result<()>`: what `ComputeNode::reconfigure` writes before
//!   it reloads: postgresql.conf (as `write_postgres_conf`), the pg_hba member
//!   block and the pg_ident member lines (as `update_pg_hba`/`update_pg_ident`,
//!   databricks settings from `spec.databricks_settings`, TLS on when
//!   `tls_config` is set). Every new content is computed and checked first; on
//!   any failure nothing is written and the error is returned.
//! - `compute_tools::tls::read_tls_digest(tls: &TlsConfig) -> anyhow::Result<CertDigest>`:
//!   one digest of the key, the certificate and (with `ca_path`) the CA file, each
//!   length-delimited, so a change to any of them (a CA-only rotation included)
//!   changes it. An unreadable file is an error.
//! - `compute_tools::tls::wait_for_tls(tls: &TlsConfig) -> CertDigest` (async):
//!   waits until `read_tls_digest` succeeds and returns its digest; the watcher
//!   starts from it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use compute_api::responses::TlsConfig;
use compute_api::spec::{ComputeSpec, MemberLogins};
use compute_tools::compute::ComputeNodeParams;
use compute_tools::config::rewrite_config_files;
use compute_tools::tls::{read_tls_digest, wait_for_tls};

const HEAD: &str = "# chelabase: member logins (cb_m_*) only from the orchestrator\n";
const MD5: &str = "host\tall\t\tall\t\tall\t\tmd5\n";

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn params(pgdata: &Path) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: "compute-test".into(),
        connstr: url::Url::parse("postgresql://cloud_admin@127.0.0.1:5432/postgres").unwrap(),
        privileged_role_name: "neon_superuser".into(),
        resize_swap_on_bind: false,
        set_disk_quota_for_fs: None,
        pgdata: pgdata.to_string_lossy().into(),
        pgbin: "/usr/local/bin/postgres".into(),
        pgversion: "17".into(),
        external_http_port: 3080,
        internal_http_port: 3081,
        remote_ext_base_url: None,
        installed_extensions_collection_interval: Arc::new(AtomicU64::new(0)),
        instance_id: None,
        pg_init_timeout: None,
        pg_isready_bin: "/usr/local/bin/pg_isready".into(),
        lakebase_mode: false,
        build_tag: "test".into(),
        control_plane_uri: None,
        config_path_test_only: None::<OsString>,
    }
}

fn spec(cns: &[&str]) -> ComputeSpec {
    let mut spec: ComputeSpec = serde_json::from_str(include_str!(
        "../../libs/compute_api/tests/cluster_spec.json"
    ))
    .unwrap();
    spec.branch_protected = true;
    spec.member_logins = Some(MemberLogins {
        allowed_cidrs: vec!["10.213.4.10/32".into()],
        client_cns: cns.iter().map(|s| s.to_string()).collect(),
    });
    spec
}

fn rewrite(dir: &Path, spec: &ComputeSpec) -> anyhow::Result<()> {
    rewrite_config_files(dir, &params(dir), spec, None, 3082, &None, false)
}

/// The three files as they are before a reconfigure.
fn seed(dir: &Path, hba: &str) -> [(PathBuf, String); 3] {
    std::fs::write(dir.join("PG_VERSION"), "17\n").unwrap();
    let files = [
        (
            dir.join("postgresql.conf"),
            "# the running config\n".to_string(),
        ),
        (dir.join("pg_hba.conf"), hba.to_string()),
        (
            dir.join("pg_ident.conf"),
            "# hand-written ident\n".to_string(),
        ),
    ];
    for (path, text) in &files {
        std::fs::write(path, text).unwrap();
    }
    files
}

/// 1: a pg_hba.conf whose block is cut short, or pg_ident lines that can't be
/// built, fail the rewrite before anything is written: postgresql.conf keeps
/// the running settings (no unloaded neon.branch_protected left on disk).
#[test]
fn a_failed_rewrite_writes_nothing() {
    let dir = fresh("f3_audit_rewrite_fails");
    let cut = seed(&dir, &format!("{HEAD}local all all trust\n{MD5}"));
    assert!(
        rewrite(&dir, &spec(&["chelabase-orchestrator"])).is_err(),
        "cut marker"
    );
    for (path, text) in &cut {
        assert_eq!(&read(path), text, "{} untouched", path.display());
    }

    let dir = fresh("f3_audit_rewrite_bad_ident");
    let ok_hba = format!("local all all trust\n{MD5}");
    let files = seed(&dir, &ok_hba);
    assert!(rewrite(&dir, &spec(&[])).is_err(), "client_cns is empty");
    for (path, text) in &files {
        assert_eq!(&read(path), text, "{} untouched", path.display());
    }
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(Path::new("./tests/tmp/f3_audit_rewrite_fails")).unwrap();
}

#[test]
fn a_rewrite_writes_all_three_files() {
    let dir = fresh("f3_audit_rewrite_ok");
    seed(&dir, &format!("local all all trust\n{MD5}"));
    rewrite(&dir, &spec(&["chelabase-orchestrator"])).unwrap();
    let conf = read(&dir.join("postgresql.conf"));
    assert!(conf.contains("neon.branch_protected"), "{conf}");
    assert!(!conf.contains("# the running config"), "{conf}");
    let hba = read(&dir.join("pg_hba.conf"));
    assert!(
        hba.starts_with(HEAD) && hba.contains("10.213.4.10/32"),
        "{hba}"
    );
    let ident = read(&dir.join("pg_ident.conf"));
    assert!(ident.contains("# hand-written ident\n"), "{ident}");
    assert!(
        ident
            .lines()
            .any(|l| l.starts_with("chelabase_member\tchelabase-orchestrator\t")),
        "{ident}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

fn tls_files(dir: &Path, key: &str, cert: &str, ca: Option<&str>) -> TlsConfig {
    std::fs::write(dir.join("k"), key).unwrap();
    std::fs::write(dir.join("c"), cert).unwrap();
    if let Some(ca) = ca {
        std::fs::write(dir.join("a"), ca).unwrap();
    }
    TlsConfig {
        key_path: dir.join("k").to_string_lossy().into(),
        cert_path: dir.join("c").to_string_lossy().into(),
        ca_path: ca.map(|_| dir.join("a").to_string_lossy().into()),
    }
}

/// 3: a change to the key, the certificate or the CA file changes the digest.
#[test]
fn the_tls_digest_covers_key_certificate_and_ca() {
    let dir = fresh("f3_audit_digest");
    let tls = tls_files(&dir, "key 1", "cert 1", Some("ca 1"));
    let first = read_tls_digest(&tls).unwrap();
    assert_eq!(read_tls_digest(&tls).unwrap(), first, "stable");

    tls_files(&dir, "key 1", "cert 1", Some("ca 2"));
    assert_ne!(read_tls_digest(&tls).unwrap(), first, "a CA-only change");
    tls_files(&dir, "key 1", "cert 1", Some("ca 1"));
    assert_eq!(read_tls_digest(&tls).unwrap(), first, "back");
    tls_files(&dir, "key 2", "cert 1", Some("ca 1"));
    assert_ne!(read_tls_digest(&tls).unwrap(), first, "a key-only change");
    tls_files(&dir, "key 1", "cert 2", Some("ca 1"));
    assert_ne!(
        read_tls_digest(&tls).unwrap(),
        first,
        "a certificate-only change"
    );

    // Length-delimited: moving bytes from one file to the next is a change.
    let a = read_tls_digest(&tls_files(&dir, "ab", "c", None)).unwrap();
    let b = read_tls_digest(&tls_files(&dir, "a", "bc", None)).unwrap();
    assert_ne!(a, b);

    std::fs::remove_file(dir.join("a")).unwrap();
    let missing_ca = TlsConfig {
        ca_path: Some(dir.join("a").to_string_lossy().into()),
        ..tls_files(&dir, "key 1", "cert 1", None)
    };
    assert!(read_tls_digest(&missing_ca).is_err(), "a missing CA file");

    let tls = tls_files(&dir, "key 1", "cert 1", Some("ca 1"));
    let waited = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(wait_for_tls(&tls));
    assert_eq!(waited, first, "the watcher starts from the same digest");
    std::fs::remove_dir_all(&dir).unwrap();
}
