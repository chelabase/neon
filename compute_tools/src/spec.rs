use std::fs::File;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use compute_api::responses::{
    ComputeConfig, ControlPlaneComputeStatus, ControlPlaneConfigResponse,
};
use compute_api::spec::MemberLogins;
use reqwest::StatusCode;
use tokio_postgres::Client;
use tracing::{error, info, instrument};

use crate::compute::ComputeNodeParams;
use crate::config;
use crate::metrics::{CPLANE_REQUESTS_TOTAL, CPlaneRequestRPC, UNKNOWN_HTTP_STATUS};
use crate::migration::{MigrationFailure, MigrationKind, MigrationRunner};
use crate::params::PG_HBA_ALL_MD5;

// Do control plane request and return response if any. In case of error it
// returns a bool flag indicating whether it makes sense to retry the request
// and a string with error message.
fn do_control_plane_request(
    uri: &str,
    jwt: &str,
) -> Result<ControlPlaneConfigResponse, (bool, String, String)> {
    let resp = reqwest::blocking::Client::new()
        .get(uri)
        .header("Authorization", format!("Bearer {jwt}"))
        .send()
        .map_err(|e| {
            (
                true,
                format!("could not perform request to control plane: {e:?}"),
                UNKNOWN_HTTP_STATUS.to_string(),
            )
        })?;

    let status = resp.status();
    match status {
        StatusCode::OK => match resp.json::<ControlPlaneConfigResponse>() {
            Ok(spec_resp) => Ok(spec_resp),
            Err(e) => Err((
                true,
                format!("could not deserialize control plane response: {e:?}"),
                status.to_string(),
            )),
        },
        StatusCode::SERVICE_UNAVAILABLE => Err((
            true,
            "control plane is temporarily unavailable".to_string(),
            status.to_string(),
        )),
        StatusCode::BAD_GATEWAY => {
            // We have a problem with intermittent 502 errors now
            // https://github.com/neondatabase/cloud/issues/2353
            // It's fine to retry GET request in this case.
            Err((
                true,
                "control plane request failed with 502".to_string(),
                status.to_string(),
            ))
        }
        // Another code, likely 500 or 404, means that compute is unknown to the control plane
        // or some internal failure happened. Doesn't make much sense to retry in this case.
        _ => Err((
            false,
            format!("unexpected control plane response status code: {status}"),
            status.to_string(),
        )),
    }
}

/// Request config from the control-plane by compute_id. If
/// `NEON_CONTROL_PLANE_TOKEN` env variable is set, it will be used for
/// authorization.
pub fn get_config_from_control_plane(base_uri: &str, compute_id: &str) -> Result<ComputeConfig> {
    let cp_uri = format!("{base_uri}/compute/api/v2/computes/{compute_id}/spec");
    let jwt: String = std::env::var("NEON_CONTROL_PLANE_TOKEN").unwrap_or_default();
    let mut attempt = 1;

    info!("getting config from control plane: {}", cp_uri);

    // Do 3 attempts to get spec from the control plane using the following logic:
    // - network error -> then retry
    // - compute id is unknown or any other error -> bail out
    // - no spec for compute yet (Empty state) -> return Ok(None)
    // - got config -> return Ok(Some(config))
    while attempt < 4 {
        let result = match do_control_plane_request(&cp_uri, &jwt) {
            Ok(config_resp) => {
                CPLANE_REQUESTS_TOTAL
                    .with_label_values(&[
                        CPlaneRequestRPC::GetConfig.as_str(),
                        &StatusCode::OK.to_string(),
                    ])
                    .inc();
                match config_resp.status {
                    ControlPlaneComputeStatus::Empty => Ok(config_resp.into()),
                    ControlPlaneComputeStatus::Attached => {
                        if config_resp.spec.is_some() {
                            Ok(config_resp.into())
                        } else {
                            bail!("compute is attached, but spec is empty")
                        }
                    }
                }
            }
            Err((retry, msg, status)) => {
                CPLANE_REQUESTS_TOTAL
                    .with_label_values(&[CPlaneRequestRPC::GetConfig.as_str(), &status])
                    .inc();
                if retry {
                    Err(anyhow!(msg))
                } else {
                    bail!(msg);
                }
            }
        };

        if let Err(e) = &result {
            error!("attempt {} to get config failed with: {}", attempt, e);
        } else {
            return result;
        }

        attempt += 1;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // All attempts failed, return error.
    Err(anyhow::anyhow!(
        "Exhausted all attempts to retrieve the config from the control plane"
    ))
}

const MEMBER_HBA_HEAD: &str = "# chelabase: member logins (cb_m_*) only from the orchestrator";
const MEMBER_HBA_TAIL: &str = "# chelabase: end of member logins";
/// The platform form of a member role's name, as a pg_hba/pg_ident regex.
const MEMBER_ROLE_RE: &str = "/^cb_m_[0-9a-f]{32}$";
/// Every spelling of the member prefix (Postgres folds unquoted names, a quoted
/// one may be any case), for the `reject` lines.
const MEMBER_PREFIX_RE: &str = "/^[Cc][Bb]_[Mm]_";
const MEMBER_IDENT_MAP: &str = "chelabase_member";

/// `<ipv4|ipv6>/<prefix>`, nothing else (no keyword, no host name, no spaces).
fn check_member_cidr(cidr: &str) -> Result<()> {
    let parsed = cidr.split_once('/').and_then(|(addr, prefix)| {
        let addr: IpAddr = addr.parse().ok()?;
        if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = prefix.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(())
    });
    parsed.ok_or_else(|| {
        anyhow!("member_logins: allowed_cidrs entry {cidr:?} isn't an address/prefix")
    })
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`: no whitespace, quotes, `/` or `#` can
/// reach pg_ident.conf.
fn check_member_cn(cn: &str) -> Result<()> {
    let mut bytes = cn.bytes();
    let ok = cn.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        bail!("member_logins: client_cns entry {cn:?} isn't a valid certificate CN")
    }
}

/// The member-login block that goes at the top of `pg_hba.conf`: one `hostssl`
/// line per allowed CIDR (`all` for an empty list) requiring SCRAM and a client
/// certificate whose CN the `chelabase_member` ident map accepts, then `reject`
/// for every other member login (TCP, replication, Unix socket). With no
/// `member_logins` or no TLS, only the `reject` lines: member logins are refused.
pub fn member_hba_block(member_logins: Option<&MemberLogins>, tls: bool) -> Result<String> {
    let mut block = format!("{MEMBER_HBA_HEAD}\n");
    if let Some(ml) = member_logins {
        for cidr in &ml.allowed_cidrs {
            check_member_cidr(cidr)?;
        }
        if tls {
            let all = ["all".to_string()];
            let cidrs = if ml.allowed_cidrs.is_empty() {
                &all[..]
            } else {
                &ml.allowed_cidrs[..]
            };
            for cidr in cidrs {
                block.push_str(&format!(
                    "hostssl\tall\t{MEMBER_ROLE_RE}\t{cidr}\tscram-sha-256\tclientcert=verify-full\tmap={MEMBER_IDENT_MAP}\n"
                ));
            }
        }
    }
    block.push_str(&format!("host\tall\t{MEMBER_PREFIX_RE}\tall\treject\n"));
    block.push_str(&format!(
        "host\treplication\t{MEMBER_PREFIX_RE}\tall\treject\n"
    ));
    block.push_str(&format!("local\tall\t{MEMBER_PREFIX_RE}\treject\n"));
    block.push_str(&format!("local\treplication\t{MEMBER_PREFIX_RE}\treject\n"));
    block.push_str(&format!("{MEMBER_HBA_TAIL}\n"));
    Ok(block)
}

/// The `pg_ident.conf` lines mapping each client certificate CN to the member
/// roles. `client_cns` must not be empty and each CN must be valid (RT3-12).
pub fn member_ident_lines(member_logins: Option<&MemberLogins>) -> Result<String> {
    let Some(ml) = member_logins else {
        return Ok(String::new());
    };
    if ml.client_cns.is_empty() {
        bail!("member_logins: client_cns is empty");
    }
    let mut lines = String::new();
    for cn in &ml.client_cns {
        check_member_cn(cn)?;
        lines.push_str(&format!("{MEMBER_IDENT_MAP}\t{cn}\t{MEMBER_ROLE_RE}\n"));
    }
    Ok(lines)
}

/// Check `pg_hba.conf` and update if needed: the member-login block first (once),
/// then the databricks include, then the catch-all `md5` line last.
pub fn update_pg_hba(
    pgdata_path: &Path,
    databricks_pg_hba: Option<&String>,
    member_logins: Option<&MemberLogins>,
    tls: bool,
) -> Result<()> {
    // XXX: consider making it a part of config.json
    let pghba_path = pgdata_path.join("pg_hba.conf");

    // Postgres uses the first matching line, so the member block goes before the
    // basebackup's `trust` lines: loopback and the Unix socket don't admit member
    // roles either.
    let block = member_hba_block(member_logins, tls)?;
    let current = match fs::read_to_string(&pghba_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).context("read pg_hba.conf"),
    };
    if current.lines().any(|line| line == MEMBER_HBA_HEAD) {
        info!("pg_hba.conf already has the member-login block");
    } else {
        fs::write(&pghba_path, format!("{block}{current}")).context("write pg_hba.conf")?;
        info!("added the member-login block to pg_hba.conf");
    }

    // Update pg_hba to contains databricks specfic settings before adding neon settings
    // PG uses the first record that matches to perform authentication, so we need to have
    // our rules before the default ones from neon.
    // See https://www.postgresql.org/docs/current/auth-pg-hba-conf.html
    if let Some(databricks_pg_hba) = databricks_pg_hba {
        if config::line_in_file(
            &pghba_path,
            &format!("include_if_exists {}\n", *databricks_pg_hba),
        )? {
            info!("updated pg_hba.conf to include databricks_pg_hba.conf");
        } else {
            info!("pg_hba.conf already included databricks_pg_hba.conf");
        }
    }

    if config::line_in_file(&pghba_path, PG_HBA_ALL_MD5)? {
        info!("updated pg_hba.conf to allow external connections");
    } else {
        info!("pg_hba.conf is up-to-date");
    }

    Ok(())
}

/// Check `pg_ident.conf` and update if needed: the member-login map lines, and
/// the databricks include.
pub fn update_pg_ident(
    pgdata_path: &Path,
    databricks_pg_ident: Option<&String>,
    member_logins: Option<&MemberLogins>,
) -> Result<()> {
    info!("checking pg_ident.conf");
    let pghba_path = pgdata_path.join("pg_ident.conf");

    for line in member_ident_lines(member_logins)?.lines() {
        if config::line_in_file(&pghba_path, line)? {
            info!("added {line:?} to pg_ident.conf");
        }
    }

    // Update pg_ident to contains databricks specfic settings
    if let Some(databricks_pg_ident) = databricks_pg_ident {
        if config::line_in_file(
            &pghba_path,
            &format!("include_if_exists {}\n", *databricks_pg_ident),
        )? {
            info!("updated pg_ident.conf to include databricks_pg_ident.conf");
        } else {
            info!("pg_ident.conf already included databricks_pg_ident.conf");
        }
    }

    Ok(())
}

/// Copy tls key_file and cert_file from k8s secret mount directory
/// to pgdata and set private key file permissions as expected by Postgres.
/// See this doc for expected permission <https://www.postgresql.org/docs/current/ssl-tcp.html>
/// K8s secrets mount on dblet does not honor permission and ownership
/// specified in the Volume or VolumeMount. So we need to explicitly copy the file and set the permissions.
pub fn copy_tls_certificates(
    key_file: &String,
    cert_file: &String,
    pgdata_path: &Path,
) -> Result<()> {
    let files = [cert_file, key_file];
    for file in files.iter() {
        let source = Path::new(file);
        let dest = pgdata_path.join(source.file_name().unwrap());
        if !dest.exists() {
            std::fs::copy(source, &dest)?;
            info!(
                "Copying tls file: {} to {}",
                &source.display(),
                &dest.display()
            );
        }
        if *file == key_file {
            // Postgres requires private key to be readable only by the owner by having
            // chmod 600 permissions.
            let permissions = Permissions::from_mode(0o600);
            fs::set_permissions(&dest, permissions)?;
            info!("Setting permission on {}.", &dest.display());
        }
    }
    Ok(())
}

/// Create a standby.signal file
pub fn add_standby_signal(pgdata_path: &Path) -> Result<()> {
    // XXX: consider making it a part of config.json
    let signalfile = pgdata_path.join("standby.signal");

    if !signalfile.exists() {
        File::create(signalfile)?;
        info!("created standby.signal");
    } else {
        info!("reused pre-existing standby.signal");
    }
    Ok(())
}

#[instrument(skip_all)]
pub async fn handle_neon_extension_upgrade(client: &mut Client) -> Result<()> {
    let query = "ALTER EXTENSION neon UPDATE";
    info!("update neon extension version with query: {}", query);
    client.simple_query(query).await?;

    Ok(())
}

/// The kind of each entry of `handle_migrations`' list, in the same order (U3).
/// A new migration that removes a privilege or an attribute is `FailOpen`.
const MIGRATION_KINDS: [MigrationKind; 12] = {
    use MigrationKind::*;
    [
        FailClosed, // 0001 neon_superuser BYPASSRLS
        FailOpen,   // 0002 INHERIT for neon_superuser members, NOBYPASSRLS for the rest
        FailClosed, // 0003 GRANT pg_create_subscription
        FailClosed, // 0004 GRANT pg_monitor
        Skip,       // 0005
        Skip,       // 0006
        Skip,       // 0007
        Skip,       // 0008
        Skip,       // 0009
        FailClosed, // 0010 GRANT EXECUTE on snapshot functions
        FailClosed, // 0011 GRANT EXECUTE ON pg_show_replication_origin_status
        FailClosed, // 0012 GRANT pg_signal_backend
    ]
};

/// One kind per entry of `handle_migrations`' list.
pub fn migration_kinds() -> Vec<MigrationKind> {
    MIGRATION_KINDS.to_vec()
}

/// Runs the pending migrations. On failure, `fatal_failure(&migration_kinds(),
/// failure.index)` says whether the start must fail.
#[instrument(skip_all)]
pub async fn handle_migrations(
    params: ComputeNodeParams,
    client: &mut Client,
    lakebase_mode: bool,
) -> Result<(), MigrationFailure> {
    info!("handle migrations");

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // !BE SURE TO ONLY ADD MIGRATIONS TO THE END OF THIS ARRAY. IF YOU DO NOT, VERY VERY BAD THINGS MAY HAPPEN!
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // Add new migrations in numerical order, with their kind in MIGRATION_KINDS
    // (the array type ties the two lengths together).
    let migrations: [&str; MIGRATION_KINDS.len()] = [
        &format!(
            include_str!("./migrations/0001-add_bypass_rls_to_privileged_role.sql"),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!("./migrations/0002-alter_roles.sql"),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!("./migrations/0003-grant_pg_create_subscription_to_privileged_role.sql"),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!("./migrations/0004-grant_pg_monitor_to_privileged_role.sql"),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!("./migrations/0005-grant_all_on_tables_to_privileged_role.sql"),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!("./migrations/0006-grant_all_on_sequences_to_privileged_role.sql"),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!(
                "./migrations/0007-grant_all_on_tables_with_grant_option_to_privileged_role.sql"
            ),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!(
                "./migrations/0008-grant_all_on_sequences_with_grant_option_to_privileged_role.sql"
            ),
            privileged_role_name = params.privileged_role_name
        ),
        include_str!("./migrations/0009-revoke_replication_for_previously_allowed_roles.sql"),
        &format!(
            include_str!(
                "./migrations/0010-grant_snapshot_synchronization_funcs_to_privileged_role.sql"
            ),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!(
                "./migrations/0011-grant_pg_show_replication_origin_status_to_privileged_role.sql"
            ),
            privileged_role_name = params.privileged_role_name
        ),
        &format!(
            include_str!("./migrations/0012-grant_pg_signal_backend_to_privileged_role.sql"),
            privileged_role_name = params.privileged_role_name
        ),
    ];

    MigrationRunner::new(client, &migrations, lakebase_mode)
        .run_migrations()
        .await
}
