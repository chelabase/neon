//! Fork round 4, K3: what `postgresql.conf` tells the neon extension and
//! DuckDB (spec §4.1 "Paths to Postgres", RT4-1, S22; plan P4, SP6).
//!
//! Pinned interfaces (the code under test):
//! - `ComputeNodeParams.internal_api_token_file: PathBuf`,
//!   `ComputeNodeParams.storage_auth_token_file: PathBuf`.
//! - `config::write_postgres_conf` (start) and `config::rewrite_config_files`
//!   (reconfigure) write, after the spec's `postgresql_conf`, `settings` and the
//!   Databricks block (so none of them wins), next to `neon.branch_protected`:
//!   `neon.compute_ctl_token_file='<internal_api_token_file>'` always;
//!   `neon.storage_auth_token_file='<storage_auth_token_file>'` when the spec has
//!   a storage token, `''` when it has none (P4); and
//!   `duckdb.disabled_filesystems='LocalFileSystem'`,
//!   `duckdb.autoinstall_known_extensions=off`,
//!   `duckdb.autoload_known_extensions=off`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use compute_api::spec::{ComputeSpec, GenericOption};
use compute_tools::compute::ComputeNodeParams;
use compute_tools::config::write_postgres_conf;

const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("pgdata")).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

fn params(dir: &Path) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: "compute-test".into(),
        connstr: url::Url::parse("postgresql://cloud_admin@127.0.0.1:5432/postgres").unwrap(),
        privileged_role_name: "neon_superuser".into(),
        resize_swap_on_bind: false,
        set_disk_quota_for_fs: None,
        pgdata: dir.join("pgdata").to_string_lossy().into(),
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
        internal_api_token_file: dir.join("compute_ctl_internal.token"),
        storage_auth_token_file: dir.join("storage_auth.token"),
    }
}

fn spec(token: Option<&str>) -> ComputeSpec {
    let mut json: serde_json::Value = serde_json::from_str(SPEC).unwrap();
    if let Some(token) = token {
        json["storage_auth_token"] = serde_json::json!(token);
    }
    serde_json::from_value(json).unwrap()
}

fn write(dir: &Path, spec: &ComputeSpec) -> String {
    let pgdata = dir.join("pgdata");
    write_postgres_conf(&pgdata, &params(dir), spec, None, 3081, &None, None, false).unwrap();
    std::fs::read_to_string(pgdata.join("postgresql.conf")).unwrap()
}

/// The value Postgres ends up with for `name` (the last line wins), unquoted.
fn last(conf: &str, name: &str) -> Option<String> {
    conf.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == name).then(|| {
                let value = value.trim();
                value
                    .strip_prefix('\'')
                    .and_then(|v| v.strip_suffix('\''))
                    .unwrap_or(value)
                    .replace("''", "'")
            })
        })
        .next_back()
}

fn quoted(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn the_token_file_paths_follow_the_spec() {
    let dir = fresh("k3_conf_paths");
    let with = write(&dir, &spec(Some("tok.en")));
    assert_eq!(
        last(&with, "neon.compute_ctl_token_file"),
        Some(quoted(&dir.join("compute_ctl_internal.token"))),
        "{with}"
    );
    assert_eq!(
        last(&with, "neon.storage_auth_token_file"),
        Some(quoted(&dir.join("storage_auth.token"))),
        "{with}"
    );
    assert!(
        !with.contains("tok.en"),
        "postgresql.conf carries the path, never the token"
    );

    // P4: no storage token, an empty path (no file, no warning); the internal
    // secret always exists.
    let without = write(&dir, &spec(None));
    assert_eq!(
        last(&without, "neon.compute_ctl_token_file"),
        Some(quoted(&dir.join("compute_ctl_internal.token")))
    );
    assert_eq!(
        last(&without, "neon.storage_auth_token_file"),
        Some(String::new()),
        "{without}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn duckdb_is_pinned_off_the_local_filesystem() {
    let dir = fresh("k3_conf_duckdb");
    let conf = write(&dir, &spec(None));
    assert_eq!(
        last(&conf, "duckdb.disabled_filesystems").as_deref(),
        Some("LocalFileSystem")
    );
    assert_eq!(
        last(&conf, "duckdb.autoinstall_known_extensions").as_deref(),
        Some("off")
    );
    assert_eq!(
        last(&conf, "duckdb.autoload_known_extensions").as_deref(),
        Some("off")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Neither the spec's `postgresql_conf` nor its `settings` can redirect the
/// token files or lift the DuckDB pins.
#[test]
fn the_spec_cannot_override_the_pinned_lines() {
    let dir = fresh("k3_conf_override");
    let mut spec = spec(Some("tok.en"));
    let overrides = [
        ("neon.compute_ctl_token_file", "/tmp/evil.token"),
        ("neon.storage_auth_token_file", "/tmp/evil.token"),
        ("duckdb.disabled_filesystems", ""),
        ("duckdb.autoinstall_known_extensions", "on"),
        ("duckdb.autoload_known_extensions", "on"),
    ];
    spec.cluster.postgresql_conf = Some(
        overrides
            .iter()
            .map(|(k, v)| format!("{k} = '{v}'"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let settings = spec.cluster.settings.get_or_insert_with(Vec::new);
    for (name, value) in overrides {
        settings.push(GenericOption {
            name: name.into(),
            value: Some(value.into()),
            vartype: "string".into(),
        });
    }
    let conf = write(&dir, &spec);
    assert_eq!(
        last(&conf, "neon.compute_ctl_token_file"),
        Some(quoted(&dir.join("compute_ctl_internal.token"))),
        "{conf}"
    );
    assert_eq!(
        last(&conf, "neon.storage_auth_token_file"),
        Some(quoted(&dir.join("storage_auth.token"))),
        "{conf}"
    );
    assert_eq!(
        last(&conf, "duckdb.disabled_filesystems").as_deref(),
        Some("LocalFileSystem")
    );
    assert_eq!(
        last(&conf, "duckdb.autoinstall_known_extensions").as_deref(),
        Some("off")
    );
    assert_eq!(
        last(&conf, "duckdb.autoload_known_extensions").as_deref(),
        Some("off")
    );
    // The pinned lines come before the temp-override include only.
    let pinned = conf.rfind("duckdb.autoload_known_extensions").unwrap();
    let include = conf.rfind("include_if_exists").unwrap();
    assert!(pinned < include, "{conf}");
    std::fs::remove_dir_all(&dir).unwrap();
}
