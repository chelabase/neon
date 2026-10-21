use anyhow::{Context, Result};
use std::fmt::Write as FmtWrite;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;
use std::io::prelude::*;
use std::path::Path;

use compute_api::responses::TlsConfig;
use compute_api::spec::{
    ComputeAudit, ComputeMode, ComputeSpec, DatabricksSettings, GenericOption,
};

use crate::compute::ComputeNodeParams;
use crate::pg_helpers::{
    DatabricksSettingsExt as _, GenericOptionExt, GenericOptionsSearch, PgOptionsSerialize,
    escape_conf_value,
};
use crate::spec;
use crate::tls::{self, SERVER_CRT, SERVER_KEY};

use utils::shard::{ShardIndex, ShardNumber};

/// Check that `line` is inside a text file and put it there if it is not.
/// Create file if it doesn't exist.
pub fn line_in_file(path: &Path, line: &str) -> Result<bool> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(false)
        .truncate(false)
        .open(path)?;
    let buf = io::BufReader::new(&file);
    let mut count: usize = 0;

    for l in buf.lines() {
        if l? == line {
            return Ok(false);
        }
        count = 1;
    }

    write!(file, "{}{}", "\n".repeat(count), line)?;
    Ok(true)
}

/// The `postgresql.conf` lines for a compute with TLS on: the key and certificate
/// copied into pgdata, and `ssl_ca_file` (the CA client certificates are checked
/// against) whenever `ca_path` is set (RT3-12).
pub fn tls_conf_lines(tls: &TlsConfig) -> String {
    // the file names are the defaults, but good to be explicit.
    let mut lines =
        format!("ssl = on\nssl_cert_file = '{SERVER_CRT}'\nssl_key_file = '{SERVER_KEY}'\n");
    if let Some(ca_path) = &tls.ca_path {
        lines.push_str(&format!("ssl_ca_file = {}\n", escape_conf_value(ca_path)));
    }
    lines
}

/// Create or completely rewrite `postgresql.conf` (through a temporary file and
/// a rename). With TLS on, the key and certificate are copied into pgdata first
/// (retried until they are a valid pair).
#[allow(clippy::too_many_arguments)]
pub fn write_postgres_conf(
    pgdata_path: &Path,
    params: &ComputeNodeParams,
    spec: &ComputeSpec,
    postgres_port: Option<u16>,
    extension_server_port: u16,
    tls_config: &Option<TlsConfig>,
    databricks_settings: Option<&DatabricksSettings>,
    lakebase_mode: bool,
) -> Result<()> {
    if let Some(tls_config) = tls_config {
        // postgres requires the keyfile to be in a secure file,
        // currently too complicated to ensure that at the VM level,
        // so we just copy them to another file instead. :shrug:
        tls::update_key_path_blocking(pgdata_path, tls_config);
    }
    let conf = render_postgres_conf(
        params,
        spec,
        postgres_port,
        extension_server_port,
        tls_config,
        databricks_settings,
        lakebase_mode,
    )?;
    write_file_atomically(&pgdata_path.join("postgresql.conf"), &conf)
}

/// Writes `data` to `path` through a temporary file and a rename.
fn write_file_atomically(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, data).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename {} into place", tmp.display()))
}

/// What [`ComputeNode::reconfigure`](crate::compute::ComputeNode::reconfigure)
/// writes before it reloads, all-or-nothing: `postgresql.conf`, the pg_hba
/// member and realtime blocks and the pg_ident member and realtime lines
/// (databricks settings from the spec). Every new content is computed and
/// checked first (and with TLS on, the key and certificate are copied once,
/// without retrying); on any failure nothing is written and the error is
/// returned.
pub fn rewrite_config_files(
    pgdata_path: &Path,
    params: &ComputeNodeParams,
    spec: &ComputeSpec,
    postgres_port: Option<u16>,
    extension_server_port: u16,
    tls_config: &Option<TlsConfig>,
    lakebase_mode: bool,
) -> Result<()> {
    let databricks_settings = spec.databricks_settings.as_ref();
    let hba = spec::plan_pg_hba(
        pgdata_path,
        databricks_settings.map(|s| &s.databricks_pg_hba),
        spec.member_logins.as_ref(),
        spec.realtime_logins.as_ref(),
        tls_config.is_some(),
    )?;
    let ident = spec::plan_pg_ident(
        pgdata_path,
        databricks_settings.map(|s| &s.databricks_pg_ident),
        spec.member_logins.as_ref(),
        spec.realtime_logins.as_ref(),
    )?;
    let conf = render_postgres_conf(
        params,
        spec,
        postgres_port,
        extension_server_port,
        tls_config,
        databricks_settings,
        lakebase_mode,
    )?;
    if let Some(tls_config) = tls_config {
        tls::copy_tls_files(pgdata_path, tls_config)
            .context("copy the TLS key and certificate into pgdata")?;
    }
    write_file_atomically(&pgdata_path.join("postgresql.conf"), &conf)?;
    // pg_ident.conf first, put back when pg_hba.conf can't be written: new hba
    // lines never map through an old ident map.
    spec::write_ident_then_hba(&ident, &hba)?;
    Ok(())
}

/// Whether `spec` carries a storage token (an empty one is none).
fn spec_has_storage_token(spec: &ComputeSpec) -> bool {
    spec.storage_auth_token
        .as_ref()
        .is_some_and(|t| !t.as_str().is_empty())
}

/// The content of `postgresql.conf`.
#[allow(clippy::too_many_arguments)]
fn render_postgres_conf(
    params: &ComputeNodeParams,
    spec: &ComputeSpec,
    postgres_port: Option<u16>,
    extension_server_port: u16,
    tls_config: &Option<TlsConfig>,
    databricks_settings: Option<&DatabricksSettings>,
    lakebase_mode: bool,
) -> Result<Vec<u8>> {
    let mut file: Vec<u8> = Vec::new();

    // Write the postgresql.conf content from the spec file as is.
    if let Some(conf) = &spec.cluster.postgresql_conf {
        writeln!(file, "{conf}")?;
    }

    // Add options for connecting to storage
    writeln!(file, "# Neon storage settings")?;
    writeln!(file)?;
    if let Some(conninfo) = &spec.pageserver_connection_info {
        // Stripe size GUC should be defined prior to connection string
        if let Some(stripe_size) = conninfo.stripe_size {
            writeln!(
                file,
                "# from compute spec's pageserver_connection_info.stripe_size field"
            )?;
            writeln!(file, "neon.stripe_size={stripe_size}")?;
        }

        let mut libpq_urls: Option<Vec<String>> = Some(Vec::new());
        let num_shards = if conninfo.shard_count.0 == 0 {
            1 // unsharded, treat it as a single shard
        } else {
            conninfo.shard_count.0
        };

        for shard_number in 0..num_shards {
            let shard_index = ShardIndex {
                shard_number: ShardNumber(shard_number),
                shard_count: conninfo.shard_count,
            };
            let info = conninfo.shards.get(&shard_index).ok_or_else(|| {
                anyhow::anyhow!(
                    "shard {shard_index} missing from pageserver_connection_info shard map"
                )
            })?;

            let first_pageserver = info
                .pageservers
                .first()
                .expect("must have at least one pageserver");

            // Add the libpq URL to the array, or if the URL is missing, reset the array
            // forgetting any previous entries. All servers must have a libpq URL, or none
            // at all.
            if let Some(url) = &first_pageserver.libpq_url {
                if let Some(ref mut urls) = libpq_urls {
                    urls.push(url.clone());
                }
            } else {
                libpq_urls = None
            }
        }
        if let Some(libpq_urls) = libpq_urls {
            writeln!(
                file,
                "# derived from compute spec's pageserver_connection_info field"
            )?;
            writeln!(
                file,
                "neon.pageserver_connstring={}",
                escape_conf_value(&libpq_urls.join(","))
            )?;
        } else {
            writeln!(file, "# no neon.pageserver_connstring")?;
        }
    } else {
        // Stripe size GUC should be defined prior to connection string
        if let Some(stripe_size) = spec.shard_stripe_size {
            writeln!(file, "# from compute spec's shard_stripe_size field")?;
            writeln!(file, "neon.stripe_size={stripe_size}")?;
        }
        if let Some(s) = &spec.pageserver_connstring {
            writeln!(file, "# from compute spec's pageserver_connstring field")?;
            writeln!(file, "neon.pageserver_connstring={}", escape_conf_value(s))?;
        }
    }

    if !spec.safekeeper_connstrings.is_empty() {
        let mut neon_safekeepers_value = String::new();
        tracing::info!(
            "safekeepers_connstrings is not zero, gen: {:?}",
            spec.safekeepers_generation
        );
        // If generation is given, prepend sk list with g#number:
        if let Some(generation) = spec.safekeepers_generation {
            write!(neon_safekeepers_value, "g#{generation}:")?;
        }
        neon_safekeepers_value.push_str(&spec.safekeeper_connstrings.join(","));
        writeln!(
            file,
            "neon.safekeepers={}",
            escape_conf_value(&neon_safekeepers_value)
        )?;
    }
    if let Some(s) = &spec.tenant_id {
        writeln!(file, "neon.tenant_id={}", escape_conf_value(&s.to_string()))?;
    }
    if let Some(s) = &spec.timeline_id {
        writeln!(
            file,
            "neon.timeline_id={}",
            escape_conf_value(&s.to_string())
        )?;
    }
    if let Some(s) = &spec.project_id {
        writeln!(file, "neon.project_id={}", escape_conf_value(s))?;
    }
    if let Some(s) = &spec.branch_id {
        writeln!(file, "neon.branch_id={}", escape_conf_value(s))?;
    }
    if let Some(s) = &spec.endpoint_id {
        writeln!(file, "neon.endpoint_id={}", escape_conf_value(s))?;
    }

    // tls
    if let Some(tls_config) = tls_config {
        write!(file, "{}", tls_conf_lines(tls_config))?;
    }

    // Locales
    if cfg!(target_os = "macos") {
        writeln!(file, "lc_messages='C'")?;
        writeln!(file, "lc_monetary='C'")?;
        writeln!(file, "lc_time='C'")?;
        writeln!(file, "lc_numeric='C'")?;
    } else {
        writeln!(file, "lc_messages='C.UTF-8'")?;
        writeln!(file, "lc_monetary='C.UTF-8'")?;
        writeln!(file, "lc_time='C.UTF-8'")?;
        writeln!(file, "lc_numeric='C.UTF-8'")?;
    }

    writeln!(file, "neon.compute_mode={}", spec.mode.to_type_str())?;
    match spec.mode {
        ComputeMode::Primary => {}
        ComputeMode::Static(lsn) => {
            // hot_standby is 'on' by default, but let's be explicit
            writeln!(file, "hot_standby=on")?;
            writeln!(file, "recovery_target_lsn='{lsn}'")?;
        }
        ComputeMode::Replica => {
            // hot_standby is 'on' by default, but let's be explicit
            writeln!(file, "hot_standby=on")?;
        }
    }

    if cfg!(target_os = "linux") {
        // Check /proc/sys/vm/overcommit_memory -- if it equals 2 (i.e. linux memory overcommit is
        // disabled), then the control plane has enabled swap and we should set
        // dynamic_shared_memory_type = 'mmap'.
        //
        // This is (maybe?) temporary - for more, see https://github.com/neondatabase/cloud/issues/12047.
        let overcommit_memory_contents = std::fs::read_to_string("/proc/sys/vm/overcommit_memory")
            // ignore any errors - they may be expected to occur under certain situations (e.g. when
            // not running in Linux).
            .unwrap_or_else(|_| String::new());
        if overcommit_memory_contents.trim() == "2" {
            let opt = GenericOption {
                name: "dynamic_shared_memory_type".to_owned(),
                value: Some("mmap".to_owned()),
                vartype: "enum".to_owned(),
            };

            writeln!(file, "{}", opt.to_pg_setting())?;
        }
    }

    writeln!(
        file,
        "neon.privileged_role_name={}",
        escape_conf_value(params.privileged_role_name.as_str())
    )?;

    // If there are any extra options in the 'settings' field, append those
    if spec.cluster.settings.is_some() {
        writeln!(file, "# Managed by compute_ctl: begin")?;
        write!(file, "{}", spec.cluster.settings.as_pg_settings())?;
        writeln!(file, "# Managed by compute_ctl: end")?;
    }

    // If base audit logging is enabled, configure it.
    // In this setup, the audit log will be written to the standard postgresql log.
    //
    // If compliance audit logging is enabled, configure pgaudit.
    //
    // Note, that this is called after the settings from spec are written.
    // This way we always override the settings from the spec
    // and don't allow the user or the control plane admin to change them.
    match spec.audit_log_level {
        ComputeAudit::Disabled => {}
        ComputeAudit::Log | ComputeAudit::Base => {
            writeln!(file, "# Managed by compute_ctl base audit settings: start")?;
            writeln!(file, "pgaudit.log='ddl,role'")?;
            // Disable logging of catalog queries to reduce the noise
            writeln!(file, "pgaudit.log_catalog=off")?;

            if let Some(libs) = spec.cluster.settings.find("shared_preload_libraries") {
                let mut extra_shared_preload_libraries = String::new();
                if !libs.contains("pgaudit") {
                    extra_shared_preload_libraries.push_str(",pgaudit");
                }
                writeln!(
                    file,
                    "shared_preload_libraries='{libs}{extra_shared_preload_libraries}'"
                )?;
            } else {
                // Typically, this should be unreacheable,
                // because we always set at least some shared_preload_libraries in the spec
                // but let's handle it explicitly anyway.
                writeln!(file, "shared_preload_libraries='neon,pgaudit'")?;
            }
            writeln!(file, "# Managed by compute_ctl base audit settings: end")?;
        }
        ComputeAudit::Hipaa | ComputeAudit::Extended | ComputeAudit::Full => {
            writeln!(
                file,
                "# Managed by compute_ctl compliance audit settings: begin"
            )?;
            // Enable logging of parameters.
            // This is very verbose and may contain sensitive data.
            if spec.audit_log_level == ComputeAudit::Full {
                writeln!(file, "pgaudit.log_parameter=on")?;
                writeln!(file, "pgaudit.log='all'")?;
            } else {
                writeln!(file, "pgaudit.log_parameter=off")?;
                writeln!(file, "pgaudit.log='all, -misc'")?;
            }
            // Disable logging of catalog queries
            // The catalog doesn't contain sensitive data, so we don't need to audit it.
            writeln!(file, "pgaudit.log_catalog=off")?;
            // Set log rotation to 5 minutes
            // TODO: tune this after performance testing
            writeln!(file, "pgaudit.log_rotation_age=5")?;

            // Enable audit logs for pg_session_jwt extension
            // TODO: Consider a good approach for shipping pg_session_jwt logs to the same sink as
            // pgAudit - additional context in https://github.com/neondatabase/cloud/issues/28863
            //
            // writeln!(file, "pg_session_jwt.audit_log=on")?;

            // Add audit shared_preload_libraries, if they are not present.
            //
            // The caller who sets the flag is responsible for ensuring that the necessary
            // shared_preload_libraries are present in the compute image,
            // otherwise the compute start will fail.
            if let Some(libs) = spec.cluster.settings.find("shared_preload_libraries") {
                let mut extra_shared_preload_libraries = String::new();
                if !libs.contains("pgaudit") {
                    extra_shared_preload_libraries.push_str(",pgaudit");
                }
                if !libs.contains("pgauditlogtofile") {
                    extra_shared_preload_libraries.push_str(",pgauditlogtofile");
                }
                writeln!(
                    file,
                    "shared_preload_libraries='{libs}{extra_shared_preload_libraries}'"
                )?;
            } else {
                // Typically, this should be unreacheable,
                // because we always set at least some shared_preload_libraries in the spec
                // but let's handle it explicitly anyway.
                writeln!(
                    file,
                    "shared_preload_libraries='neon,pgaudit,pgauditlogtofile'"
                )?;
            }
            writeln!(
                file,
                "# Managed by compute_ctl compliance audit settings: end"
            )?;
        }
    }

    writeln!(file, "neon.extension_server_port={extension_server_port}")?;

    if spec.drop_subscriptions_before_start {
        writeln!(file, "neon.disable_logical_replication_subscribers=true")?;
    } else {
        // be explicit about the default value
        writeln!(file, "neon.disable_logical_replication_subscribers=false")?;
    }

    // We need Postgres to send logs to rsyslog so that we can forward them
    // further to customers' log aggregation systems.
    if spec.logs_export_host.is_some() {
        writeln!(file, "log_destination='stderr,syslog'")?;
    }

    if lakebase_mode {
        // Explicitly set the port based on the connstr, overriding any previous port setting.
        // Note: It is important that we don't specify a different port again after this.
        let port = postgres_port.expect("port must be present in connstr");
        writeln!(file, "port = {port}")?;

        // This is databricks specific settings.
        // This should be at the end of the file but before `compute_ctl_temp_override.conf` below
        // so that it can override any settings above.
        // `compute_ctl_temp_override.conf` is intended to override any settings above during specific operations.
        // To prevent potential breakage in the future, we keep it above `compute_ctl_temp_override.conf`.
        writeln!(file, "# Databricks settings start")?;
        if let Some(settings) = databricks_settings {
            writeln!(file, "{}", settings.as_pg_settings())?;
        }
        writeln!(file, "# Databricks settings end")?;
    }

    // U14: the branch's protection, read by the neon extension's DDL handler
    // (PGC_SIGHUP, so no session can change it). Written after the spec's own
    // `postgresql_conf` and `settings` (and the Databricks settings), so none of
    // them can override it.
    writeln!(
        file,
        "neon.branch_protected={}",
        if spec.branch_protected { "on" } else { "off" }
    )?;

    // §4.1: where the neon extension reads the internal API secret and the
    // storage token (the paths, never the tokens; `PGC_POSTMASTER`). Written
    // after the spec's settings, so none of them can redirect a reader. A
    // compute without a storage token gets an empty path (P4: no file, no
    // warning); storage auth can't change without a restart (SP6), so every
    // rewrite writes the same two lines.
    writeln!(
        file,
        "neon.compute_ctl_token_file={}",
        escape_conf_value(&params.internal_api_token_file.to_string_lossy())
    )?;
    let storage_token_file = if spec_has_storage_token(spec) {
        params
            .storage_auth_token_file
            .to_string_lossy()
            .into_owned()
    } else {
        String::new()
    };
    writeln!(
        file,
        "neon.storage_auth_token_file={}",
        escape_conf_value(&storage_token_file)
    )?;

    // RT4-1, S22: DuckDB (pg_duckdb, `extensions-all`) never reads local files
    // or installs and loads its own extensions, whatever the spec says
    // (`PGC_SUSET`: no owner can change them in a session).
    writeln!(file, "duckdb.disabled_filesystems='LocalFileSystem'")?;
    writeln!(file, "duckdb.autoinstall_known_extensions=off")?;
    writeln!(file, "duckdb.autoload_known_extensions=off")?;

    // This is essential to keep this line at the end of the file,
    // because it is intended to override any settings above.
    writeln!(file, "include_if_exists = 'compute_ctl_temp_override.conf'")?;

    Ok(file)
}

pub fn with_compute_ctl_tmp_override<F>(pgdata_path: &Path, options: &str, exec: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let path = pgdata_path.join("compute_ctl_temp_override.conf");
    let mut file = File::create(path)?;
    write!(file, "{options}")?;

    let res = exec();

    file.set_len(0)?;

    res
}
