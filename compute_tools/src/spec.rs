use std::fs::File;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use compute_api::responses::{
    COMPUTE_CAPABILITIES, COMPUTE_CAPABILITIES_HEADER, ComputeConfig, ControlPlaneComputeStatus,
    ControlPlaneConfigResponse,
};
use compute_api::spec::MemberLogins;
use reqwest::StatusCode;
use tokio_postgres::Client;
use tracing::{error, info, instrument};

use crate::compute::ComputeNodeParams;
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
        // RT4-2: what this compute_ctl can do, so the control plane gives it
        // expiring storage tokens only when it can refresh them.
        .header(COMPUTE_CAPABILITIES_HEADER, COMPUTE_CAPABILITIES.join(","))
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

const REALTIME_HBA_HEAD: &str = "# chelabase: realtime logins";
const REALTIME_HBA_TAIL: &str = "# chelabase: end of realtime logins";
/// The realtime decoder's role (W31); its ident map has the same name.
const REALTIME_ROLE: &str = "chelabase_realtime";
const REALTIME_IDENT_MAP: &str = "chelabase_realtime";
const REALTIME_IDENT_HEAD: &str = "# chelabase: realtime certificate map (chelabase_realtime)";
const REALTIME_IDENT_TAIL: &str = "# chelabase: end of realtime certificate map";

/// `<ipv4|ipv6>/<prefix>`, nothing else (no keyword, no host name, no spaces);
/// an error names `field` (`member_logins`, `realtime_logins`).
fn check_cidr(field: &str, cidr: &str) -> Result<()> {
    let parsed = cidr.split_once('/').and_then(|(addr, prefix)| {
        let addr: IpAddr = addr.parse().ok()?;
        if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = prefix.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(())
    });
    parsed.ok_or_else(|| anyhow!("{field}: allowed_cidrs entry {cidr:?} isn't an address/prefix"))
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`: no whitespace, quotes, `/` or `#` can
/// reach pg_ident.conf; an error names `field`.
fn check_cn(field: &str, cn: &str) -> Result<()> {
    let mut bytes = cn.bytes();
    let ok = cn.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        bail!("{field}: client_cns entry {cn:?} isn't a valid certificate CN")
    }
}

/// One login rule set of `pg_hba.conf`, between its `head` and `tail` markers:
/// with `logins` and `tls`, one `hostssl` line per allowed CIDR (`all` for an
/// empty list) for `allow_role`, requiring SCRAM and a client certificate
/// whose CN the `map` ident map accepts; then `reject` for every other login of
/// `reject_role` (TCP, replication, Unix socket). The CIDRs are checked
/// whatever `tls` is; an error names `field`.
struct HbaRules<'a> {
    head: &'a str,
    tail: &'a str,
    allow_role: &'a str,
    reject_role: &'a str,
    map: &'a str,
    field: &'a str,
}

impl HbaRules<'_> {
    fn block(&self, logins: Option<&MemberLogins>, tls: bool) -> Result<String> {
        let Self {
            head,
            tail,
            allow_role,
            reject_role,
            map,
            field,
        } = self;
        let mut block = format!("{head}\n");
        if let Some(logins) = logins {
            for cidr in &logins.allowed_cidrs {
                check_cidr(field, cidr)?;
            }
            if tls {
                let all = ["all".to_string()];
                let cidrs = if logins.allowed_cidrs.is_empty() {
                    &all[..]
                } else {
                    &logins.allowed_cidrs[..]
                };
                for cidr in cidrs {
                    block.push_str(&format!(
                        "hostssl\tall\t{allow_role}\t{cidr}\tscram-sha-256\tclientcert=verify-full\tmap={map}\n"
                    ));
                }
            }
        }
        block.push_str(&format!("host\tall\t{reject_role}\tall\treject\n"));
        block.push_str(&format!("host\treplication\t{reject_role}\tall\treject\n"));
        block.push_str(&format!("local\tall\t{reject_role}\treject\n"));
        block.push_str(&format!("local\treplication\t{reject_role}\treject\n"));
        block.push_str(&format!("{tail}\n"));
        Ok(block)
    }
}

const MEMBER_HBA: HbaRules<'static> = HbaRules {
    head: MEMBER_HBA_HEAD,
    tail: MEMBER_HBA_TAIL,
    allow_role: MEMBER_ROLE_RE,
    reject_role: MEMBER_PREFIX_RE,
    map: MEMBER_IDENT_MAP,
    field: "member_logins",
};

const REALTIME_HBA: HbaRules<'static> = HbaRules {
    head: REALTIME_HBA_HEAD,
    tail: REALTIME_HBA_TAIL,
    allow_role: REALTIME_ROLE,
    reject_role: REALTIME_ROLE,
    map: REALTIME_IDENT_MAP,
    field: "realtime_logins",
};

/// The member-login block that goes at the top of `pg_hba.conf`: one `hostssl`
/// line per allowed CIDR (`all` for an empty list) requiring SCRAM and a client
/// certificate whose CN the `chelabase_member` ident map accepts, then `reject`
/// for every other member login (TCP, replication, Unix socket). With no
/// `member_logins` or no TLS, only the `reject` lines: member logins are refused.
pub fn member_hba_block(member_logins: Option<&MemberLogins>, tls: bool) -> Result<String> {
    MEMBER_HBA.block(member_logins, tls)
}

/// The realtime-login block that goes right after the member block (W31): one
/// `hostssl` line per allowed CIDR (`all` for an empty list) for
/// `chelabase_realtime`, requiring SCRAM and a client certificate whose CN the
/// `chelabase_realtime` ident map accepts, then `reject` for every other login
/// of the role (TCP, replication, Unix socket). With no `realtime_logins` or no
/// TLS, only the `reject` lines: the role can't log in.
pub fn realtime_hba_block(realtime_logins: Option<&MemberLogins>, tls: bool) -> Result<String> {
    REALTIME_HBA.block(realtime_logins, tls)
}

/// The `pg_ident.conf` lines of `map`, one per CN of `logins`, to `role`.
/// `client_cns` must not be empty and each CN must be valid (RT3-12); an error
/// names `field`.
fn ident_lines(
    logins: Option<&MemberLogins>,
    map: &str,
    role: &str,
    field: &str,
) -> Result<String> {
    let Some(logins) = logins else {
        return Ok(String::new());
    };
    if logins.client_cns.is_empty() {
        bail!("{field}: client_cns is empty");
    }
    let mut lines = String::new();
    for cn in &logins.client_cns {
        check_cn(field, cn)?;
        lines.push_str(&format!("{map}\t{cn}\t{role}\n"));
    }
    Ok(lines)
}

/// The `pg_ident.conf` lines mapping each client certificate CN to the member
/// roles. `client_cns` must not be empty and each CN must be valid (RT3-12).
pub fn member_ident_lines(member_logins: Option<&MemberLogins>) -> Result<String> {
    ident_lines(
        member_logins,
        MEMBER_IDENT_MAP,
        MEMBER_ROLE_RE,
        "member_logins",
    )
}

/// The `pg_ident.conf` lines mapping each client certificate CN to
/// `chelabase_realtime` (W31). `client_cns` must not be empty and each CN must
/// be valid.
pub fn realtime_ident_lines(realtime_logins: Option<&MemberLogins>) -> Result<String> {
    ident_lines(
        realtime_logins,
        REALTIME_IDENT_MAP,
        REALTIME_ROLE,
        "realtime_logins",
    )
}

const MEMBER_IDENT_HEAD: &str = "# chelabase: member certificate map (chelabase_member)";
const MEMBER_IDENT_TAIL: &str = "# chelabase: end of member certificate map";

/// Where the `head` and `tail` marker lines of `text` are: each `head` line's
/// start offset and each `tail` line's end offset (after its line end). A line
/// matches without its `\n` or `\r\n`.
fn marker_offsets(text: &str, head: &str, tail: &str) -> (Vec<usize>, Vec<usize>) {
    let mut heads = Vec::new();
    let mut tails = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let bare = line.strip_suffix('\n').unwrap_or(line);
        let bare = bare.strip_suffix('\r').unwrap_or(bare);
        if bare == head {
            heads.push(offset);
        } else if bare == tail {
            tails.push(offset + line.len());
        }
        offset += line.len();
    }
    (heads, tails)
}

/// `current` with the text from the `head` line through the `tail` line (both
/// included) replaced by `block`; without either marker, `block` goes in at
/// byte offset `absent_at` (a line start). A block cut short (one marker
/// without the other, a marker twice, the end before the start) is an error
/// naming `file`: nothing is guessed.
fn replace_marked_block(
    current: &str,
    head: &str,
    tail: &str,
    block: &str,
    file: &str,
    absent_at: usize,
) -> Result<String> {
    let (heads, tails) = marker_offsets(current, head, tail);
    match (heads.as_slice(), tails.as_slice()) {
        ([], []) => Ok(format!(
            "{}{block}{}",
            &current[..absent_at],
            &current[absent_at..]
        )),
        ([start], [end]) if start < end => {
            Ok(format!("{}{block}{}", &current[..*start], &current[*end..]))
        }
        _ => bail!(
            "{file}: the chelabase block {head:?} is cut short or repeated ({} start and {} end \
             markers, expected one of each, in order); fix the file by hand",
            heads.len(),
            tails.len()
        ),
    }
}

/// The end of the (one) `tail` marker line of `text`, where a block that
/// follows that block goes; `0` without it.
fn after_marked_block(text: &str, head: &str, tail: &str) -> usize {
    marker_offsets(text, head, tail)
        .1
        .first()
        .copied()
        .unwrap_or(0)
}

/// Writes `text` to `path` through a temporary file and a rename, so Postgres
/// never reads a half-written file; does nothing when the content is already
/// `text`.
fn write_conf_file(path: &Path, current: &str, text: &str) -> Result<bool> {
    if current == text {
        return Ok(false);
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(&tmp, meta.permissions());
    }
    fs::rename(&tmp, path).with_context(|| format!("rename {} into place", tmp.display()))?;
    Ok(true)
}

fn read_conf_file(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// The major version in `<pgdata>/PG_VERSION`, when it can be read.
fn pgdata_major_version(pgdata_path: &Path) -> Option<u32> {
    fs::read_to_string(pgdata_path.join("PG_VERSION"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Check `pg_hba.conf` and update if needed: the member-login block first, the
/// realtime-login block right after it (each replaced between its own markers
/// when it's there, the rest of the file kept byte for byte), then the
/// databricks include, then the catch-all `md5` line last.
///
/// The blocks' `hostssl … clientcert=verify-full map=…` lines need v17 (older
/// majors refuse `map=` with a client certificate check); below v17, or when
/// `PG_VERSION` can't be read, or without TLS, each block holds only its
/// `reject` lines: those logins are refused (fails closed).
pub fn update_pg_hba(
    pgdata_path: &Path,
    databricks_pg_hba: Option<&String>,
    member_logins: Option<&MemberLogins>,
    realtime_logins: Option<&MemberLogins>,
    tls: bool,
) -> Result<()> {
    plan_pg_hba(
        pgdata_path,
        databricks_pg_hba,
        member_logins,
        realtime_logins,
        tls,
    )?
    .write()?;
    Ok(())
}

/// Check `pg_ident.conf` and update if needed: the member-login map lines and,
/// right after them, the realtime map lines (each between their own markers,
/// replaced as a whole so a CN dropped from `client_cns` stops mapping; the
/// rest of the file kept), and the databricks include.
pub fn update_pg_ident(
    pgdata_path: &Path,
    databricks_pg_ident: Option<&String>,
    member_logins: Option<&MemberLogins>,
    realtime_logins: Option<&MemberLogins>,
) -> Result<()> {
    plan_pg_ident(
        pgdata_path,
        databricks_pg_ident,
        member_logins,
        realtime_logins,
    )?
    .write()?;
    Ok(())
}

/// A configuration file's new content, computed and checked but not written yet,
/// so several files can be rewritten all-or-nothing.
pub(crate) struct ConfRewrite {
    path: std::path::PathBuf,
    current: String,
    updated: String,
}

impl ConfRewrite {
    /// Writes the new content (through a temporary file and a rename) when it
    /// differs from the file's; returns whether it wrote.
    pub(crate) fn write(&self) -> Result<bool> {
        let wrote = write_conf_file(&self.path, &self.current, &self.updated)?;
        if wrote {
            info!("updated {}", self.path.display());
        }
        Ok(wrote)
    }
}

/// `text` with `line` (compared without its line end) added at the end unless a
/// line of `text` already equals it.
fn with_line(text: String, line: &str) -> String {
    let bare = line.trim_end_matches('\n');
    if text.lines().any(|l| l == bare) {
        return text;
    }
    let sep = if text.is_empty() { "" } else { "\n" };
    format!("{text}{sep}{line}")
}

/// The new `pg_hba.conf` (see [`update_pg_hba`]), not written.
pub(crate) fn plan_pg_hba(
    pgdata_path: &Path,
    databricks_pg_hba: Option<&String>,
    member_logins: Option<&MemberLogins>,
    realtime_logins: Option<&MemberLogins>,
    tls: bool,
) -> Result<ConfRewrite> {
    // XXX: consider making it a part of config.json
    let pghba_path = pgdata_path.join("pg_hba.conf");

    let major = pgdata_major_version(pgdata_path);
    let cert_tls = tls && major.is_some_and(|v| v >= 17);
    if tls && !cert_tls && (member_logins.is_some() || realtime_logins.is_some()) {
        tracing::warn!(
            ?major,
            "member and realtime logins need PostgreSQL 17 or later: pg_hba.conf only rejects them"
        );
    }

    // Postgres uses the first matching line, so the member block goes first and
    // the realtime block right after it, both before the basebackup's `trust`
    // lines: loopback and the Unix socket don't admit those roles either.
    let member_block = member_hba_block(member_logins, cert_tls)?;
    let realtime_block = realtime_hba_block(realtime_logins, cert_tls)?;
    let current = read_conf_file(&pghba_path)?;
    let updated = replace_marked_block(
        &current,
        MEMBER_HBA_HEAD,
        MEMBER_HBA_TAIL,
        &member_block,
        "pg_hba.conf",
        0,
    )?;
    let after_member = after_marked_block(&updated, MEMBER_HBA_HEAD, MEMBER_HBA_TAIL);
    let updated = replace_marked_block(
        &updated,
        REALTIME_HBA_HEAD,
        REALTIME_HBA_TAIL,
        &realtime_block,
        "pg_hba.conf",
        after_member,
    )?;

    // Update pg_hba to contains databricks specfic settings before adding neon settings
    // PG uses the first record that matches to perform authentication, so we need to have
    // our rules before the default ones from neon.
    // See https://www.postgresql.org/docs/current/auth-pg-hba-conf.html
    let updated = match databricks_pg_hba {
        Some(databricks_pg_hba) => with_line(
            updated,
            &format!("include_if_exists {}\n", *databricks_pg_hba),
        ),
        None => updated,
    };
    let updated = with_line(updated, PG_HBA_ALL_MD5);

    Ok(ConfRewrite {
        path: pghba_path,
        current,
        updated,
    })
}

/// `text` without its lines of the ident map `map` when it has neither the
/// `head` nor the `tail` marker (a file from before that block existed);
/// unchanged otherwise.
fn without_unmarked_map(text: String, head: &str, tail: &str, map: &str) -> String {
    if text.lines().any(|l| l == head || l == tail) {
        return text;
    }
    text.split_inclusive('\n')
        .filter(|l| l.split_whitespace().next() != Some(map))
        .collect()
}

/// The new `pg_ident.conf` (see [`update_pg_ident`]), not written.
pub(crate) fn plan_pg_ident(
    pgdata_path: &Path,
    databricks_pg_ident: Option<&String>,
    member_logins: Option<&MemberLogins>,
    realtime_logins: Option<&MemberLogins>,
) -> Result<ConfRewrite> {
    let pgident_path = pgdata_path.join("pg_ident.conf");

    let member_block = format!(
        "{MEMBER_IDENT_HEAD}\n{}{MEMBER_IDENT_TAIL}\n",
        member_ident_lines(member_logins)?
    );
    let realtime_block = format!(
        "{REALTIME_IDENT_HEAD}\n{}{REALTIME_IDENT_TAIL}\n",
        realtime_ident_lines(realtime_logins)?
    );
    let current = read_conf_file(&pgident_path)?;
    // A file written before a block's markers existed: its unmarked lines of
    // that map go, the block replaces them (so no CN stays mapped outside it).
    let base = without_unmarked_map(
        current.clone(),
        MEMBER_IDENT_HEAD,
        MEMBER_IDENT_TAIL,
        MEMBER_IDENT_MAP,
    );
    let base = without_unmarked_map(
        base,
        REALTIME_IDENT_HEAD,
        REALTIME_IDENT_TAIL,
        REALTIME_IDENT_MAP,
    );
    let updated = replace_marked_block(
        &base,
        MEMBER_IDENT_HEAD,
        MEMBER_IDENT_TAIL,
        &member_block,
        "pg_ident.conf",
        0,
    )?;
    let after_member = after_marked_block(&updated, MEMBER_IDENT_HEAD, MEMBER_IDENT_TAIL);
    let updated = replace_marked_block(
        &updated,
        REALTIME_IDENT_HEAD,
        REALTIME_IDENT_TAIL,
        &realtime_block,
        "pg_ident.conf",
        after_member,
    )?;

    // Update pg_ident to contains databricks specfic settings
    let updated = match databricks_pg_ident {
        Some(databricks_pg_ident) => with_line(
            updated,
            &format!("include_if_exists {}\n", *databricks_pg_ident),
        ),
        None => updated,
    };

    Ok(ConfRewrite {
        path: pgident_path,
        current,
        updated,
    })
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
