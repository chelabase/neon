//! Fork round 4, final fix round (lane F1): edge cases beyond the RED set (the
//! coder's own tests).
//!
//! - `rewrite_config_files`: when `pg_hba.conf` can't be written after
//!   `pg_ident.conf` was, `pg_ident.conf` is put back (an ident file that
//!   didn't exist is removed again), and the error is returned.
//! - `update_pg_hba_and_ident` (the start path) writes ident before hba too.
//! - `plan_pg_hba`: with no member block in the file, both blocks go at the
//!   top in order; a realtime block cut short is still an error, nothing written.
//! - `remove_stale_temp_files`: an entry `<name>.tmp.` (empty suffix) is kept;
//!   a directory named like a stale temp file is an error (nothing guessed).
//! - The endpoint storage token from the `neon.endpoint_storage_token` setting
//!   is redacted in `ParsedSpec`'s `Debug` too.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use compute_api::spec::{ComputeSpec, MemberLogins};
use compute_tools::compute::{ComputeNodeParams, ParsedSpec};
use compute_tools::config::rewrite_config_files;
use compute_tools::spec::{
    member_hba_block, realtime_hba_block, update_pg_hba, update_pg_hba_and_ident,
};
use compute_tools::token_file::{
    INTERNAL_API_TOKEN_FILE, STORAGE_AUTH_TOKEN_FILE, remove_stale_temp_files,
};
use serde_json::{Value, json};

const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");
const ORCH: &str = "chelabase-orchestrator";
const RT_CN: &str = "chelabase-realtime";
const MD5: &str = "host\tall\t\tall\t\tall\t\tmd5\n";
const BASEBACKUP: &str = "local   all             all                                     trust\n\
host    all             all             127.0.0.1/32            trust\n";

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn pgdata(name: &str) -> PathBuf {
    let dir = fresh(name);
    fs::write(dir.join("PG_VERSION"), "17\n").unwrap();
    dir
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

fn logins(cidrs: &[&str], cns: &[&str]) -> MemberLogins {
    MemberLogins {
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        client_cns: cns.iter().map(|s| s.to_string()).collect(),
    }
}

fn params(dir: &Path) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: "compute-f1-edges".into(),
        connstr: url::Url::parse("postgresql://cloud_admin@127.0.0.1:1/postgres").unwrap(),
        privileged_role_name: "neon_superuser".into(),
        resize_swap_on_bind: false,
        set_disk_quota_for_fs: None,
        pgdata: dir.to_string_lossy().into(),
        pgbin: "/nonexistent/postgres".into(),
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
        internal_api_token_file: dir.with_file_name(INTERNAL_API_TOKEN_FILE),
        storage_auth_token_file: dir.with_file_name(STORAGE_AUTH_TOKEN_FILE),
    }
}

fn spec() -> ComputeSpec {
    let mut json: Value = serde_json::from_str(SPEC).unwrap();
    json["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
    let mut spec: ComputeSpec = serde_json::from_value(json).unwrap();
    spec.member_logins = Some(logins(&["10.213.4.10/32"], &[ORCH]));
    spec.realtime_logins = Some(logins(&["10.213.4.12/32"], &[RT_CN]));
    spec
}

/// The hba file's temporary file name is taken by a directory, so its write
/// fails after the ident file's: the ident file is put back as it was.
#[test]
fn a_failed_hba_write_puts_the_old_ident_back() {
    let dir = pgdata("f1_edges_hba_fails");
    fs::write(dir.join("postgresql.conf"), "# the running config\n").unwrap();
    fs::write(dir.join("pg_hba.conf"), format!("{BASEBACKUP}{MD5}")).unwrap();
    fs::write(dir.join("pg_ident.conf"), "# hand-written ident\n").unwrap();
    let hba_before = read(&dir.join("pg_hba.conf"));
    let ident_before = read(&dir.join("pg_ident.conf"));
    fs::create_dir(dir.join(format!("pg_hba.tmp.{}", std::process::id()))).unwrap();

    let result = rewrite_config_files(&dir, &params(&dir), &spec(), None, 3082, &None, false);
    assert!(result.is_err(), "pg_hba.conf can't be written");
    assert_eq!(read(&dir.join("pg_hba.conf")), hba_before);
    assert_eq!(
        read(&dir.join("pg_ident.conf")),
        ident_before,
        "pg_ident.conf must be put back"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// An ident file that didn't exist before is removed again on the rollback.
#[test]
fn a_failed_hba_write_removes_a_new_ident_file() {
    let dir = pgdata("f1_edges_hba_fails_no_ident");
    fs::write(dir.join("postgresql.conf"), "# the running config\n").unwrap();
    fs::write(dir.join("pg_hba.conf"), format!("{BASEBACKUP}{MD5}")).unwrap();
    fs::create_dir(dir.join(format!("pg_hba.tmp.{}", std::process::id()))).unwrap();

    let result = rewrite_config_files(&dir, &params(&dir), &spec(), None, 3082, &None, false);
    assert!(result.is_err(), "pg_hba.conf can't be written");
    assert!(
        !dir.join("pg_ident.conf").exists(),
        "a pg_ident.conf written for the failed rewrite stays behind"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// The start path's writer: ident first, rolled back when hba fails; both
/// written otherwise.
#[test]
fn the_start_path_writes_ident_before_hba() {
    let dir = pgdata("f1_edges_start_path");
    let s = spec();
    fs::write(dir.join("pg_hba.conf"), format!("{BASEBACKUP}{MD5}")).unwrap();
    fs::write(dir.join("pg_ident.conf"), "# hand-written ident\n").unwrap();
    let blocker = dir.join(format!("pg_hba.tmp.{}", std::process::id()));
    fs::create_dir(&blocker).unwrap();
    let args = (s.member_logins.as_ref(), s.realtime_logins.as_ref());
    update_pg_hba_and_ident(&dir, None, None, args.0, args.1, true).unwrap_err();
    assert_eq!(read(&dir.join("pg_ident.conf")), "# hand-written ident\n");
    assert_eq!(read(&dir.join("pg_hba.conf")), format!("{BASEBACKUP}{MD5}"));

    fs::remove_dir(&blocker).unwrap();
    update_pg_hba_and_ident(&dir, None, None, args.0, args.1, true).unwrap();
    assert!(read(&dir.join("pg_ident.conf")).contains(RT_CN));
    assert!(read(&dir.join("pg_hba.conf")).contains("chelabase_realtime"));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn without_a_member_block_both_blocks_go_at_the_top_in_order() {
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    let rl = logins(&["10.213.4.12/32"], &[RT_CN]);
    let member = member_hba_block(Some(&ml), true).unwrap();
    let rt = realtime_hba_block(Some(&rl), true).unwrap();
    // No member block, a realtime block below the trust lines.
    let dir = pgdata("f1_edges_no_member");
    let hba = dir.join("pg_hba.conf");
    fs::write(&hba, format!("{BASEBACKUP}{rt}{MD5}")).unwrap();
    update_pg_hba(&dir, None, Some(&ml), Some(&rl), true).unwrap();
    assert_eq!(read(&hba), format!("{member}{rt}{BASEBACKUP}{MD5}"));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_realtime_block_cut_short_is_still_an_error() {
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    let rl = logins(&["10.213.4.12/32"], &[RT_CN]);
    let member = member_hba_block(Some(&ml), true).unwrap();
    let rt = realtime_hba_block(Some(&rl), true).unwrap();
    // Only the head line of the realtime block, below the trust lines.
    let head = rt.lines().next().unwrap();
    let dir = pgdata("f1_edges_rt_cut");
    let hba = dir.join("pg_hba.conf");
    let text = format!("{member}{BASEBACKUP}{head}\n{MD5}");
    fs::write(&hba, &text).unwrap();
    update_pg_hba(&dir, None, Some(&ml), Some(&rl), true).unwrap_err();
    assert_eq!(read(&hba), text, "nothing is written");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_stale_temp_file_sweep_edges() {
    let dir = fresh("f1_edges_tmp_sweep");
    let token = dir.join(STORAGE_AUTH_TOKEN_FILE);
    // An empty suffix names no writer's pid: kept.
    fs::write(dir.join("storage_auth.token.tmp."), "kept\n").unwrap();
    remove_stale_temp_files(&token).unwrap();
    assert!(dir.join("storage_auth.token.tmp.").exists());

    // A directory named like a stale temp file: an error, left alone.
    fs::create_dir(dir.join("storage_auth.token.tmp.5")).unwrap();
    remove_stale_temp_files(&token).unwrap_err();
    assert!(dir.join("storage_auth.token.tmp.5").is_dir());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_endpoint_storage_token_from_the_settings_is_redacted() {
    let mut json: Value = serde_json::from_str(SPEC).unwrap();
    json["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
    json["cluster"]["settings"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name": "neon.endpoint_storage_token",
            "value": "f1SettingsNeedle",
            "vartype": "string"
        }));
    let spec: ComputeSpec = serde_json::from_value(json).unwrap();
    let pspec = ParsedSpec::try_from(spec).unwrap();
    assert_eq!(
        pspec.endpoint_storage_token.as_ref().map(|t| t.as_str()),
        Some("f1SettingsNeedle")
    );
    let text = format!("{:?}", pspec.endpoint_storage_token);
    assert!(!text.contains("f1SettingsNeedle"), "{text}");
}
