//! U14: the branch's protection reaches the compute as a flag.
//!
//! Pinned interfaces (the code under test):
//! - `compute_api::spec::ComputeSpec.branch_protected: bool`, `#[serde(default)]`
//!   (false when the field is absent).
//! - `compute_tools::config::write_postgres_conf` (called at start and by
//!   `ComputeNode::reconfigure`, which reloads afterwards) writes
//!   `neon.branch_protected = on|off` from the spec, after the spec's own
//!   `postgresql_conf` and `settings`, so neither can override it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use compute_api::spec::{ComputeSpec, GenericOption};
use compute_tools::compute::ComputeNodeParams;
use compute_tools::config::write_postgres_conf;

const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");

fn spec() -> ComputeSpec {
    serde_json::from_str(SPEC).unwrap()
}

#[test]
fn a_spec_without_the_field_is_unprotected() {
    assert!(!SPEC.contains("branch_protected"));
    assert!(!spec().branch_protected);
    let mut json: serde_json::Value = serde_json::from_str(SPEC).unwrap();
    json["branch_protected"] = serde_json::Value::Bool(true);
    let protected: ComputeSpec = serde_json::from_value(json).unwrap();
    assert!(protected.branch_protected);
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

/// The value Postgres ends up with: the last `neon.branch_protected` line wins.
fn last_flag(conf: &str) -> Option<bool> {
    conf.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            if key.trim() != "neon.branch_protected" {
                return None;
            }
            match value
                .trim()
                .trim_matches('\'')
                .to_ascii_lowercase()
                .as_str()
            {
                "on" | "true" | "1" => Some(true),
                "off" | "false" | "0" => Some(false),
                other => panic!("neon.branch_protected = {other:?}"),
            }
        })
        .next_back()
}

fn write(pgdata: &Path, spec: &ComputeSpec) -> String {
    write_postgres_conf(
        pgdata,
        &params(pgdata),
        spec,
        None,
        3082,
        &None,
        None,
        false,
    )
    .unwrap();
    std::fs::read_to_string(pgdata.join("postgresql.conf")).unwrap()
}

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn postgresql_conf_carries_the_flag_and_reconfigure_rewrites_it() {
    let dir = fresh("f3_branch_flag");
    let mut spec = spec();

    spec.branch_protected = true;
    assert_eq!(
        last_flag(&write(&dir, &spec)),
        Some(true),
        "start, protected"
    );
    // Reconfigure writes the file again from the new spec.
    spec.branch_protected = false;
    assert_eq!(last_flag(&write(&dir, &spec)), Some(false), "unprotected");
    spec.branch_protected = true;
    assert_eq!(
        last_flag(&write(&dir, &spec)),
        Some(true),
        "protected again"
    );

    // The spec's own postgresql_conf and settings can't turn it off.
    spec.cluster.postgresql_conf = Some("neon.branch_protected = off".into());
    spec.cluster
        .settings
        .get_or_insert_with(Vec::new)
        .push(GenericOption {
            name: "neon.branch_protected".into(),
            value: Some("off".into()),
            vartype: "bool".into(),
        });
    assert_eq!(
        last_flag(&write(&dir, &spec)),
        Some(true),
        "not overridable"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
