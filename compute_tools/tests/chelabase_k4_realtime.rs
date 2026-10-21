//! Fork round 4, K4 (W31, spec §10): the realtime pg_hba and pg_ident blocks.
//!
//! Pinned interfaces (the code under test, `compute_tools::spec`):
//! - `realtime_hba_block(realtime_logins: Option<&MemberLogins>, tls: bool) ->
//!   anyhow::Result<String>`: `# chelabase: realtime logins`, one
//!   `hostssl\tall\tchelabase_realtime\t<cidr>\tscram-sha-256\tclientcert=verify-full\tmap=chelabase_realtime`
//!   line per CIDR (`all` for an empty list) when `realtime_logins` is set and
//!   `tls`, then the four reject lines (`host all`, `host replication`, `local
//!   all`, `local replication`, role `chelabase_realtime`), then
//!   `# chelabase: end of realtime logins`; fields tab-separated, each line `\n`
//!   ended, as the member block. CIDRs are checked as the member block's (an
//!   error naming `realtime_logins`), also when `tls` is off.
//! - `realtime_ident_lines(realtime_logins: Option<&MemberLogins>) ->
//!   anyhow::Result<String>`: one `chelabase_realtime\t<cn>\tchelabase_realtime\n`
//!   per CN; `None` → `""`; an empty `client_cns` or a CN the member check
//!   refuses → an error naming `realtime_logins`.
//! - `update_pg_hba(pgdata, databricks_pg_hba, member_logins, realtime_logins,
//!   tls)` and `update_pg_ident(pgdata, databricks_pg_ident, member_logins,
//!   realtime_logins)` (a new argument after `member_logins`); the realtime
//!   blocks are replaced between their own markers; a file without them gets
//!   the realtime block right after the member block (pg_hba: so before the
//!   basebackup's `trust` lines; pg_ident: right after the member map block,
//!   `# chelabase: realtime certificate map (chelabase_realtime)` …
//!   `# chelabase: end of realtime certificate map`). Below v17 (or no
//!   `PG_VERSION`) or without TLS, the reject lines only. A realtime block cut
//!   short is an error naming the file, nothing written.
//! - `config::rewrite_config_files` (unchanged signature) writes both blocks
//!   from `spec.realtime_logins`, all-or-nothing.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use compute_api::responses::TlsConfig;
use compute_api::spec::{ComputeSpec, MemberLogins};
use compute_tools::compute::ComputeNodeParams;
use compute_tools::config::rewrite_config_files;
use compute_tools::spec::{
    member_hba_block, member_ident_lines, realtime_hba_block, realtime_ident_lines, update_pg_hba,
    update_pg_ident,
};

const HEAD: &str = "# chelabase: realtime logins\n";
const REJECT: &str = "host\tall\tchelabase_realtime\tall\treject\n\
host\treplication\tchelabase_realtime\tall\treject\n\
local\tall\tchelabase_realtime\treject\n\
local\treplication\tchelabase_realtime\treject\n";
const TAIL: &str = "# chelabase: end of realtime logins\n";
const IDENT_HEAD: &str = "# chelabase: realtime certificate map (chelabase_realtime)\n";
const IDENT_TAIL: &str = "# chelabase: end of realtime certificate map\n";
const MEMBER_IDENT_TAIL: &str = "# chelabase: end of member certificate map\n";
const MD5: &str = "host\tall\t\tall\t\tall\t\tmd5\n";
const RT_CN: &str = "chelabase-realtime";
const ORCH: &str = "chelabase-orchestrator";
/// The basebackup's sample pg_hba.conf rules.
const BASEBACKUP: &str = "local   all             all                                     trust\n\
host    all             all             127.0.0.1/32            trust\n\
host    all             all             ::1/128                 trust\n\
local   replication     all                                     trust\n\
host    replication     all             127.0.0.1/32            trust\n\
host    replication     all             ::1/128                 trust\n";

fn allow(cidr: &str) -> String {
    format!(
        "hostssl\tall\tchelabase_realtime\t{cidr}\tscram-sha-256\tclientcert=verify-full\tmap=chelabase_realtime\n"
    )
}

fn logins(cidrs: &[&str], cns: &[&str]) -> MemberLogins {
    MemberLogins {
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        client_cns: cns.iter().map(|s| s.to_string()).collect(),
    }
}

/// A fresh `./tests/tmp/<name>` pgdata, with `PG_VERSION` when given.
fn pgdata(name: &str, pg_version: Option<&str>) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    if let Some(v) = pg_version {
        std::fs::write(dir.join("PG_VERSION"), format!("{v}\n")).unwrap();
    }
    dir
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn member_ident_block(ml: Option<&MemberLogins>) -> String {
    format!(
        "# chelabase: member certificate map (chelabase_member)\n{}{MEMBER_IDENT_TAIL}",
        member_ident_lines(ml).unwrap()
    )
}

fn realtime_ident_block(rl: Option<&MemberLogins>) -> String {
    format!(
        "{IDENT_HEAD}{}{IDENT_TAIL}",
        realtime_ident_lines(rl).unwrap()
    )
}

// ---------------------------------------------------------------------------
// The blocks
// ---------------------------------------------------------------------------

#[test]
fn the_realtime_block_allows_each_cidr_then_rejects() {
    let rl = logins(&["10.213.4.12/32", "10.213.4.11/32"], &[RT_CN]);
    assert_eq!(
        realtime_hba_block(Some(&rl), true).unwrap(),
        format!(
            "{HEAD}{}{}{REJECT}{TAIL}",
            allow("10.213.4.12/32"),
            allow("10.213.4.11/32")
        )
    );
    assert_eq!(
        realtime_hba_block(Some(&logins(&[], &[RT_CN])), true).unwrap(),
        format!("{HEAD}{}{REJECT}{TAIL}", allow("all")),
        "an empty list: no address rule"
    );
    assert_eq!(
        realtime_hba_block(None, true).unwrap(),
        format!("{HEAD}{REJECT}{TAIL}"),
        "no realtime_logins: refused"
    );
    assert_eq!(
        realtime_hba_block(Some(&rl), false).unwrap(),
        format!("{HEAD}{REJECT}{TAIL}"),
        "no TLS: refused"
    );
    assert!(
        realtime_hba_block(Some(&logins(&["fd00::12/128"], &[RT_CN])), true)
            .unwrap()
            .contains("\tfd00::12/128\t")
    );
    // The realtime block never names a member role, and the member block never
    // names chelabase_realtime: each rule set is its own.
    let block = realtime_hba_block(Some(&rl), true).unwrap();
    assert!(
        !block.contains("cb_m_") && !block.contains("[Cc][Bb]"),
        "{block}"
    );
    let member = member_hba_block(Some(&logins(&["10.213.4.10/32"], &[ORCH])), true).unwrap();
    assert!(!member.contains("chelabase_realtime"), "{member}");
}

#[test]
fn bad_realtime_cidrs_and_cns_fail() {
    for cidr in [
        "x",
        "10.0.0.1",
        "10.0.0.1/33",
        "fd00::1/129",
        "10.0.0.1/32 trust",
        "10.0.0.1/32\ttrust",
        "all",
        "samenet",
        "",
    ] {
        for tls in [true, false] {
            let err = realtime_hba_block(Some(&logins(&[cidr], &[RT_CN])), tls)
                .expect_err(&format!("{cidr:?}, tls {tls}: must fail"));
            assert!(
                format!("{err:#}").contains("realtime_logins"),
                "{cidr:?}: the error names realtime_logins: {err:#}"
            );
        }
    }
    for cns in [
        vec![],
        vec!["a b"],
        vec!["a#b"],
        vec![""],
        vec!["-x"],
        vec!["x/y"],
        vec!["chelabase-realtime", "x\ny"],
    ] {
        let err = realtime_ident_lines(Some(&logins(&[], &cns)))
            .expect_err(&format!("{cns:?}: must fail"));
        assert!(
            format!("{err:#}").contains("realtime_logins"),
            "{cns:?}: the error names realtime_logins: {err:#}"
        );
    }
}

#[test]
fn ident_lines_map_each_cn_to_the_realtime_role() {
    assert_eq!(
        realtime_ident_lines(Some(&logins(&[], &[RT_CN, "chelabase-realtime-2"]))).unwrap(),
        "chelabase_realtime\tchelabase-realtime\tchelabase_realtime\n\
chelabase_realtime\tchelabase-realtime-2\tchelabase_realtime\n"
    );
    assert_eq!(realtime_ident_lines(None).unwrap(), "");
}

// ---------------------------------------------------------------------------
// pg_hba.conf: position, rewrites, versions
// ---------------------------------------------------------------------------

/// A basebackup's pg_hba.conf: the member block, then the realtime block, then
/// the `trust` lines, the catch-all last; idempotent.
#[test]
fn the_realtime_block_goes_right_after_the_member_block() {
    let dir = pgdata("k4_rt_hba_fresh", Some("17"));
    std::fs::write(dir.join("pg_hba.conf"), format!("{BASEBACKUP}{MD5}")).unwrap();
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    let rl = logins(&["10.213.4.12/32"], &[RT_CN]);
    update_pg_hba(&dir, None, Some(&ml), Some(&rl), true).unwrap();
    let want = format!(
        "{}{}{BASEBACKUP}{MD5}",
        member_hba_block(Some(&ml), true).unwrap(),
        realtime_hba_block(Some(&rl), true).unwrap()
    );
    let text = read(&dir.join("pg_hba.conf"));
    assert_eq!(text, want);
    update_pg_hba(&dir, None, Some(&ml), Some(&rl), true).unwrap();
    assert_eq!(read(&dir.join("pg_hba.conf")), text, "idempotent");
    assert_eq!(text.matches(HEAD.trim_end()).count(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A pg_hba.conf written before round 4 (the member block only): the realtime
/// block goes right after it, everything else is kept byte for byte.
#[test]
fn a_file_without_the_realtime_block_gets_it_after_the_member_block() {
    let dir = pgdata("k4_rt_hba_legacy", Some("17"));
    let hba = dir.join("pg_hba.conf");
    let before = "# edited by hand, above the blocks\n";
    let after = "# edited by hand, below the blocks\n";
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    let member = member_hba_block(Some(&ml), true).unwrap();
    std::fs::write(&hba, format!("{before}{member}{after}{BASEBACKUP}{MD5}")).unwrap();
    update_pg_hba(&dir, None, Some(&ml), None, true).unwrap();
    assert_eq!(
        read(&hba),
        format!("{before}{member}{HEAD}{REJECT}{TAIL}{after}{BASEBACKUP}{MD5}")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Each block is replaced between its own markers; the other block and the
/// rest of the file are kept; N entries to 0 and back; absent → reject only.
/// A line edited in between the blocks follows the realtime block (final fix
/// round: nothing may sit between them, as a hand-written `trust` line there
/// would admit `chelabase_realtime` before its reject lines).
#[test]
fn each_block_is_rewritten_between_its_own_markers() {
    let dir = pgdata("k4_rt_hba_replace", Some("17"));
    let hba = dir.join("pg_hba.conf");
    let before = "# edited by hand, above the blocks\n";
    let between = "# edited by hand, between the blocks\n";
    let after = "local   all   all   trust\n# edited by hand, below the blocks\n\t \n";
    let m1 = logins(&["10.213.4.10/32"], &[ORCH]);
    let m2 = logins(&["10.213.4.10/32", "10.213.4.11/32"], &[ORCH]);
    let r1 = logins(&["10.213.4.12/32", "10.213.4.11/32"], &[RT_CN]);
    let r2 = logins(&["fd00::12/128"], &[RT_CN]);
    let expect = |m: Option<&MemberLogins>, r: Option<&MemberLogins>| {
        format!(
            "{before}{}{}{between}{after}{MD5}",
            member_hba_block(m, true).unwrap(),
            realtime_hba_block(r, true).unwrap()
        )
    };
    std::fs::write(
        &hba,
        format!(
            "{before}{}{between}{}{after}{MD5}",
            member_hba_block(Some(&m1), true).unwrap(),
            realtime_hba_block(Some(&r1), true).unwrap()
        ),
    )
    .unwrap();

    update_pg_hba(&dir, None, Some(&m1), Some(&r2), true).unwrap();
    assert_eq!(read(&hba), expect(Some(&m1), Some(&r2)), "realtime only");
    update_pg_hba(&dir, None, Some(&m2), Some(&r2), true).unwrap();
    assert_eq!(read(&hba), expect(Some(&m2), Some(&r2)), "member only");
    update_pg_hba(&dir, None, Some(&m2), Some(&r2), true).unwrap();
    assert_eq!(read(&hba), expect(Some(&m2), Some(&r2)), "idempotent");

    let empty = logins(&[], &[RT_CN]);
    update_pg_hba(&dir, None, Some(&m2), Some(&empty), true).unwrap();
    assert_eq!(read(&hba), expect(Some(&m2), Some(&empty)), "0 entries");
    assert!(read(&hba).contains(&allow("all")));
    update_pg_hba(&dir, None, Some(&m2), Some(&r1), true).unwrap();
    assert_eq!(read(&hba), expect(Some(&m2), Some(&r1)), "and back");

    update_pg_hba(&dir, None, Some(&m2), None, true).unwrap();
    assert_eq!(read(&hba), expect(Some(&m2), None), "absent: reject only");
    assert!(!read(&hba).contains("hostssl\tall\tchelabase_realtime"));
    update_pg_hba(&dir, None, None, Some(&r1), true).unwrap();
    assert_eq!(
        read(&hba),
        expect(None, Some(&r1)),
        "no member_logins doesn't touch realtime's"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Without TLS, below v17 or without a readable `PG_VERSION`: reject lines
/// only (fails closed), as the member block.
#[test]
fn no_tls_or_below_v17_only_rejects() {
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    let rl = logins(&["10.213.4.12/32"], &[RT_CN]);
    let reject_only = format!("{HEAD}{REJECT}{TAIL}");
    for (i, version) in [Some("16"), Some("15"), Some("14"), None, Some("garbage")]
        .iter()
        .enumerate()
    {
        let dir = pgdata(&format!("k4_rt_hba_version_{i}"), *version);
        update_pg_hba(&dir, None, Some(&ml), Some(&rl), true).unwrap();
        let text = read(&dir.join("pg_hba.conf"));
        assert!(
            text.contains(&reject_only),
            "PG_VERSION {version:?}: reject lines only:\n{text}"
        );
        assert!(!text.contains("hostssl"), "PG_VERSION {version:?}:\n{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
    let dir = pgdata("k4_rt_hba_no_tls", Some("17"));
    update_pg_hba(&dir, None, Some(&ml), Some(&rl), false).unwrap();
    let text = read(&dir.join("pg_hba.conf"));
    assert!(text.contains(&reject_only), "no TLS:\n{text}");
    assert!(!text.contains("hostssl"), "no TLS:\n{text}");
    std::fs::remove_dir_all(&dir).unwrap();

    let dir = pgdata("k4_rt_hba_v17", Some("17"));
    update_pg_hba(&dir, None, Some(&ml), Some(&rl), true).unwrap();
    assert!(read(&dir.join("pg_hba.conf")).contains(&allow("10.213.4.12/32")));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A realtime block cut short (one marker without the other, a marker twice,
/// the end before the start) is a clear error; the file is left as it was.
#[test]
fn a_cut_realtime_block_is_refused() {
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    let rl = logins(&["10.213.4.12/32"], &[RT_CN]);
    let member = member_hba_block(Some(&ml), true).unwrap();
    let block = realtime_hba_block(Some(&rl), true).unwrap();
    let head_only = block.replace(TAIL, "");
    let tail_only = block.replace(HEAD, "");
    let cases = [
        ("start marker only", format!("{member}{head_only}{MD5}")),
        ("end marker only", format!("{member}{tail_only}{MD5}")),
        (
            "end before start",
            format!("{member}{TAIL}{REJECT}{HEAD}{MD5}"),
        ),
        (
            "a second start inside",
            format!("{member}{head_only}{block}{MD5}"),
        ),
    ];
    for (i, (what, text)) in cases.iter().enumerate() {
        let dir = pgdata(&format!("k4_rt_hba_cut_{i}"), Some("17"));
        let hba = dir.join("pg_hba.conf");
        std::fs::write(&hba, text).unwrap();
        let err = update_pg_hba(&dir, None, Some(&ml), Some(&rl), true)
            .expect_err(&format!("{what}: must fail"));
        assert!(
            format!("{err:#}").contains("pg_hba.conf"),
            "{what}: the error names the file: {err:#}"
        );
        assert_eq!(&read(&hba), text, "{what}: the file is untouched");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

// ---------------------------------------------------------------------------
// pg_ident.conf
// ---------------------------------------------------------------------------

/// The realtime map follows `client_cns` (a CN dropped from the list stops
/// mapping), sits right after the member map, keeps every other line; the
/// member map is untouched by it.
#[test]
fn update_pg_ident_writes_the_realtime_map() {
    let dir = pgdata("k4_rt_ident", Some("17"));
    let ident = dir.join("pg_ident.conf");
    let mine = "# edited by hand\nmymap\tbob\tbob\n";
    std::fs::write(&ident, mine).unwrap();
    let ml = logins(&[], &[ORCH]);
    let ra = logins(&[], &["cn-a", "cn-b"]);
    let rb = logins(&[], &["cn-b", "cn-c"]);

    update_pg_ident(&dir, None, Some(&ml), Some(&ra)).unwrap();
    assert_eq!(
        read(&ident),
        format!(
            "{}{}{mine}",
            member_ident_block(Some(&ml)),
            realtime_ident_block(Some(&ra))
        )
    );
    update_pg_ident(&dir, None, Some(&ml), Some(&rb)).unwrap();
    let text = read(&ident);
    assert_eq!(
        text,
        format!(
            "{}{}{mine}",
            member_ident_block(Some(&ml)),
            realtime_ident_block(Some(&rb))
        ),
        "cn-a is gone"
    );
    assert!(!text.contains("cn-a"), "{text}");
    update_pg_ident(&dir, None, Some(&ml), Some(&rb)).unwrap();
    assert_eq!(read(&ident), text, "idempotent");

    update_pg_ident(&dir, None, Some(&ml), None).unwrap();
    assert_eq!(
        read(&ident),
        format!(
            "{}{IDENT_HEAD}{IDENT_TAIL}{mine}",
            member_ident_block(Some(&ml))
        ),
        "no realtime_logins: no CN mapped"
    );
    update_pg_ident(&dir, None, None, Some(&rb)).unwrap();
    assert_eq!(
        read(&ident),
        format!(
            "{}{}{mine}",
            member_ident_block(None),
            realtime_ident_block(Some(&rb))
        ),
        "no member_logins doesn't touch realtime's"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn update_pg_ident_refuses_bad_cns_and_a_cut_block() {
    let ml = logins(&[], &[ORCH]);
    let dir = pgdata("k4_rt_ident_bad_cn", Some("17"));
    let ident = dir.join("pg_ident.conf");
    std::fs::write(&ident, "mymap\tbob\tbob\n").unwrap();
    for cns in [vec![], vec!["a#b"]] {
        let err = update_pg_ident(&dir, None, Some(&ml), Some(&logins(&[], &cns)))
            .expect_err(&format!("{cns:?}: must fail"));
        assert!(format!("{err:#}").contains("realtime_logins"), "{err:#}");
        assert_eq!(read(&ident), "mymap\tbob\tbob\n", "untouched");
    }
    std::fs::remove_dir_all(&dir).unwrap();

    let rl = logins(&[], &[RT_CN]);
    let member = member_ident_block(Some(&ml));
    for (i, text) in [
        format!("{member}{IDENT_HEAD}mymap\tbob\tbob\n"),
        format!("{member}mymap\tbob\tbob\n{IDENT_TAIL}"),
        format!("{member}{IDENT_TAIL}{IDENT_HEAD}"),
        format!("{member}{IDENT_HEAD}{IDENT_HEAD}{IDENT_TAIL}"),
    ]
    .iter()
    .enumerate()
    {
        let dir = pgdata(&format!("k4_rt_ident_cut_{i}"), Some("17"));
        let ident = dir.join("pg_ident.conf");
        std::fs::write(&ident, text).unwrap();
        let err = update_pg_ident(&dir, None, Some(&ml), Some(&rl)).unwrap_err();
        assert!(format!("{err:#}").contains("pg_ident.conf"), "{err:#}");
        assert_eq!(&read(&ident), text);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

// ---------------------------------------------------------------------------
// The reconfigure path (`rewrite_config_files`)
// ---------------------------------------------------------------------------

fn params(pgdata: &Path) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: "compute-k4".into(),
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
        internal_api_token_file: pgdata.with_file_name("compute_ctl_internal.token"),
        storage_auth_token_file: pgdata.with_file_name("storage_auth.token"),
    }
}

fn spec(realtime: Option<MemberLogins>) -> ComputeSpec {
    let mut spec: ComputeSpec = serde_json::from_str(include_str!(
        "../../libs/compute_api/tests/cluster_spec.json"
    ))
    .unwrap();
    spec.member_logins = Some(logins(&["10.213.4.10/32"], &[ORCH]));
    spec.realtime_logins = realtime;
    spec
}

/// A self-signed P-256 pair in `<dir>/tls/`, as the compute's mounted files.
fn tls_pair(dir: &Path) -> TlsConfig {
    let tls = dir.join("tls");
    std::fs::create_dir_all(&tls).unwrap();
    let out = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.crt",
            "-days",
            "2",
            "-subj",
            "/CN=compute",
        ])
        .current_dir(&tls)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    TlsConfig {
        key_path: tls.join("server.key").to_string_lossy().into(),
        cert_path: tls.join("server.crt").to_string_lossy().into(),
        ca_path: None,
    }
}

fn seed(dir: &Path) {
    std::fs::write(dir.join("postgresql.conf"), "# the running config\n").unwrap();
    std::fs::write(dir.join("pg_hba.conf"), format!("{BASEBACKUP}{MD5}")).unwrap();
    std::fs::write(dir.join("pg_ident.conf"), "# hand-written ident\n").unwrap();
}

/// A reconfigure writes the realtime blocks from the spec (a CIDR change
/// applies at the next push) and rewrites them in place.
#[test]
fn a_reconfigure_rewrites_the_realtime_blocks() {
    let dir = pgdata("k4_rt_rewrite", Some("17"));
    seed(&dir);
    let tls = Some(tls_pair(&dir));
    let r1 = logins(&["10.213.4.12/32", "10.213.4.11/32"], &[RT_CN]);
    rewrite_config_files(
        &dir,
        &params(&dir),
        &spec(Some(r1.clone())),
        None,
        3082,
        &tls,
        false,
    )
    .unwrap();
    let hba = read(&dir.join("pg_hba.conf"));
    let member = member_hba_block(Some(&logins(&["10.213.4.10/32"], &[ORCH])), true).unwrap();
    assert!(
        hba.starts_with(&format!(
            "{member}{}",
            realtime_hba_block(Some(&r1), true).unwrap()
        )),
        "{hba}"
    );
    let ident = read(&dir.join("pg_ident.conf"));
    assert!(ident.contains(&realtime_ident_block(Some(&r1))), "{ident}");

    let r2 = logins(&["10.213.4.13/32"], &[RT_CN]);
    rewrite_config_files(
        &dir,
        &params(&dir),
        &spec(Some(r2.clone())),
        None,
        3082,
        &tls,
        false,
    )
    .unwrap();
    let hba = read(&dir.join("pg_hba.conf"));
    assert!(hba.contains(&allow("10.213.4.13/32")), "{hba}");
    assert!(
        !hba.contains("10.213.4.12/32"),
        "the old list is gone:\n{hba}"
    );
    assert_eq!(hba.matches(HEAD.trim_end()).count(), 1, "{hba}");

    rewrite_config_files(&dir, &params(&dir), &spec(None), None, 3082, &tls, false).unwrap();
    let hba = read(&dir.join("pg_hba.conf"));
    assert!(hba.contains(&format!("{HEAD}{REJECT}{TAIL}")), "{hba}");
    assert!(!hba.contains("hostssl\tall\tchelabase_realtime"), "{hba}");
    let ident = read(&dir.join("pg_ident.conf"));
    assert!(
        ident.contains(&format!("{IDENT_HEAD}{IDENT_TAIL}")),
        "{ident}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Without TLS a reconfigure writes the reject-only block; a realtime list that
/// can't be written fails the rewrite before anything is written.
#[test]
fn a_reconfigure_without_tls_or_with_a_bad_list() {
    let dir = pgdata("k4_rt_rewrite_no_tls", Some("17"));
    seed(&dir);
    let rl = logins(&["10.213.4.12/32"], &[RT_CN]);
    rewrite_config_files(
        &dir,
        &params(&dir),
        &spec(Some(rl)),
        None,
        3082,
        &None,
        false,
    )
    .unwrap();
    let hba = read(&dir.join("pg_hba.conf"));
    assert!(hba.contains(&format!("{HEAD}{REJECT}{TAIL}")), "{hba}");
    std::fs::remove_dir_all(&dir).unwrap();

    for (i, bad) in [
        logins(&["10.0.0.1/33"], &[RT_CN]),
        logins(&["10.213.4.12/32"], &[]),
        logins(&["10.213.4.12/32"], &["a#b"]),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = pgdata(&format!("k4_rt_rewrite_bad_{i}"), Some("17"));
        seed(&dir);
        let files = ["postgresql.conf", "pg_hba.conf", "pg_ident.conf"]
            .map(|f| (dir.join(f), read(&dir.join(f))));
        let tls = Some(tls_pair(&dir));
        assert!(
            rewrite_config_files(
                &dir,
                &params(&dir),
                &spec(Some(bad.clone())),
                None,
                3082,
                &tls,
                false
            )
            .is_err(),
            "{bad:?}"
        );
        for (path, text) in &files {
            assert_eq!(&read(path), text, "{bad:?}: {} untouched", path.display());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
