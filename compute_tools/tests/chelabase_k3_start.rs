//! Fork round 4, K3: the storage token file on the start and reconfigure paths
//! (spec §8 "The token file", RT4-3, RT4-11).
//!
//! Pinned interfaces (the code under test):
//! - `ComputeNodeParams.internal_api_token_file: PathBuf`,
//!   `ComputeNodeParams.storage_auth_token_file: PathBuf`.
//! - `ComputeNode::prepare_pgdata` writes `postgresql.conf` (with
//!   `neon.storage_auth_token_file`) and the storage token file before it runs
//!   `postgres --sync-safekeepers`, which gets no `NEON_AUTH_TOKEN`.
//! - `ComputeNode::reconfigure` writes the spec's storage token to the file
//!   before anything else, so a reconfigure that fails later leaves the new
//!   token in place.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use compute_api::responses::{ComputeConfig, ComputeCtlConfig};
use compute_tools::compute::{ComputeNode, ComputeNodeParams};
use serde_json::{Value, json};

const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");
const TOKEN: &str = "k3start.eyJ0IjoxfQ.c2ln";

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn params(dir: &Path, pgbin: &Path) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: "compute-test".into(),
        connstr: url::Url::parse("postgresql://cloud_admin@127.0.0.1:1/postgres").unwrap(),
        privileged_role_name: "neon_superuser".into(),
        resize_swap_on_bind: false,
        set_disk_quota_for_fs: None,
        pgdata: dir.join("pgdata").to_string_lossy().into(),
        pgbin: pgbin.to_string_lossy().into(),
        pgversion: "17".into(),
        external_http_port: 3080,
        internal_http_port: 3081,
        remote_ext_base_url: None,
        installed_extensions_collection_interval: Arc::new(AtomicU64::new(0)),
        instance_id: None,
        pg_init_timeout: None,
        pg_isready_bin: "/nonexistent/pg_isready".into(),
        lakebase_mode: false,
        build_tag: "test".into(),
        control_plane_uri: None,
        config_path_test_only: None::<OsString>,
        internal_api_token_file: dir.join("compute_ctl_internal.token"),
        storage_auth_token_file: dir.join("storage_auth.token"),
    }
}

fn spec_json(token: &str) -> Value {
    let mut json: Value = serde_json::from_str(SPEC).unwrap();
    json["storage_auth_token"] = json!(token);
    // Nothing listens on port 1: the fast sync check fails at once.
    json["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
    // No pgbouncer to tune in the test.
    json.as_object_mut().unwrap().remove("pgbouncer_settings");
    json
}

fn compute(params: ComputeNodeParams, token: &str) -> Arc<ComputeNode> {
    let compute = ComputeNode::new(
        params,
        ComputeConfig {
            spec: Some(serde_json::from_value(spec_json(token)).unwrap()),
            compute_ctl_config: ComputeCtlConfig::default(),
        },
    )
    .unwrap();
    Arc::new(compute)
}

/// RT4-11: by the time `postgres --sync-safekeepers` runs, `postgresql.conf`
/// names the token file and the file holds the token; the process has no
/// `NEON_AUTH_TOKEN`. A fake `postgres` records what it sees and reports an LSN.
#[test]
fn the_sync_finds_the_config_and_the_token_file() {
    let dir = fresh("k3_start_sync");
    let token_file = dir.join("storage_auth.token");
    let pgbin = dir.join("fake_postgres");
    fs::write(
        &pgbin,
        format!(
            "#!/bin/sh\n\
             d='{d}'\n\
             echo \"$@\" > \"$d/sync.args\"\n\
             env > \"$d/sync.env\"\n\
             cat '{t}' > \"$d/sync.token\" 2>/dev/null || echo MISSING > \"$d/sync.token\"\n\
             cat \"$PGDATA/postgresql.conf\" > \"$d/sync.conf\" 2>/dev/null || echo MISSING > \"$d/sync.conf\"\n\
             touch \"$d/sync.done\"\n\
             echo 0/16B9188\n",
            d = dir.display(),
            t = token_file.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&pgbin, fs::Permissions::from_mode(0o755)).unwrap();

    let compute = compute(params(&dir, &pgbin), TOKEN);
    let state = compute.state.lock().unwrap().clone();
    // The basebackup after the sync retries against a pageserver that isn't
    // there; the thread is left behind and ends with the test process.
    let worker = Arc::clone(&compute);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let _ = worker.prepare_pgdata(&state);
    });

    let deadline = Instant::now() + Duration::from_secs(60);
    while !dir.join("sync.done").exists() {
        assert!(
            Instant::now() < deadline,
            "postgres --sync-safekeepers never ran"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let read = |name: &str| fs::read_to_string(dir.join(name)).unwrap();
    assert_eq!(read("sync.args").trim(), "--sync-safekeepers");
    assert_eq!(
        read("sync.token"),
        format!("{TOKEN}\n"),
        "the token file before the sync"
    );
    let conf = read("sync.conf");
    let line = format!("neon.storage_auth_token_file='{}'", token_file.display());
    assert!(
        conf.lines().any(|l| l.replace(' ', "") == line),
        "postgresql.conf names the file before the sync:\n{conf}"
    );
    assert!(
        !conf.contains("k3start"),
        "postgresql.conf never carries the token"
    );
    let env = read("sync.env");
    assert!(
        !env.lines().any(|l| l.starts_with("NEON_AUTH_TOKEN=")),
        "--sync-safekeepers got NEON_AUTH_TOKEN"
    );
    assert!(
        !env.contains("k3start"),
        "the token is in the sync's environment"
    );
}

/// RT4-3: the new token is in place even when a later reconfigure step fails
/// (here: there is no pgdata to rewrite the config in).
#[test]
fn a_reconfigure_writes_the_token_first() {
    let dir = fresh("k3_start_reconfigure");
    let token_file = dir.join("storage_auth.token");
    fs::write(&token_file, "k3start.old\n").unwrap();
    let compute = compute(params(&dir, Path::new("/nonexistent/postgres")), TOKEN);
    assert!(!dir.join("pgdata").exists());

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    assert!(
        compute.reconfigure().is_err(),
        "no pgdata: the config rewrite fails"
    );
    assert_eq!(
        fs::read_to_string(&token_file).unwrap(),
        format!("{TOKEN}\n")
    );
    let mode = fs::metadata(&token_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    fs::remove_dir_all(&dir).unwrap();
}
