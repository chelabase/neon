//! Round 3: the member pg_hba block and pg_ident lines, TLS lines and keys, migration kinds.

use std::path::{Path, PathBuf};

use compute_api::responses::TlsConfig;
use compute_api::spec::MemberLogins;
use compute_tools::config::tls_conf_lines;
use compute_tools::migration::{
    MIGRATION_CONN_OPTIONS, MigrationFailure, MigrationKind, fatal_failure,
};
use compute_tools::spec::{
    member_hba_block, member_ident_lines, migration_kinds, update_pg_hba, update_pg_ident,
};
use compute_tools::tls::{reload_tls_files, verify_key_cert};

const HEAD: &str = "# chelabase: member logins (cb_m_*) only from the orchestrator\n";
const REJECT: &str = "host\tall\t/^[Cc][Bb]_[Mm]_\tall\treject\n\
host\treplication\t/^[Cc][Bb]_[Mm]_\tall\treject\n\
local\tall\t/^[Cc][Bb]_[Mm]_\treject\n\
local\treplication\t/^[Cc][Bb]_[Mm]_\treject\n";
const TAIL: &str = "# chelabase: end of member logins\n";

fn allow(cidr: &str) -> String {
    format!(
        "hostssl\tall\t/^cb_m_[0-9a-f]{{32}}$\t{cidr}\tscram-sha-256\tclientcert=verify-full\tmap=chelabase_member\n"
    )
}

fn logins(cidrs: &[&str], cns: &[&str]) -> MemberLogins {
    MemberLogins {
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        client_cns: cns.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn the_block_allows_each_cidr_then_rejects() {
    let ml = logins(
        &["10.213.4.10/32", "10.213.4.11/32"],
        &["chelabase-orchestrator"],
    );
    assert_eq!(
        member_hba_block(Some(&ml), true).unwrap(),
        format!(
            "{HEAD}{}{}{REJECT}{TAIL}",
            allow("10.213.4.10/32"),
            allow("10.213.4.11/32")
        )
    );
    let empty = logins(&[], &["chelabase-orchestrator"]);
    assert_eq!(
        member_hba_block(Some(&empty), true).unwrap(),
        format!("{HEAD}{}{REJECT}{TAIL}", allow("all"))
    );
    assert_eq!(
        member_hba_block(None, true).unwrap(),
        format!("{HEAD}{REJECT}{TAIL}"),
        "no spec: refused"
    );
    assert_eq!(
        member_hba_block(Some(&ml), false).unwrap(),
        format!("{HEAD}{REJECT}{TAIL}"),
        "no TLS: refused"
    );
    assert!(
        member_hba_block(
            Some(&logins(&["fd00::10/128"], &["chelabase-orchestrator"])),
            true
        )
        .unwrap()
        .contains("\tfd00::10/128\t")
    );
}

#[test]
fn bad_cidrs_and_cns_fail() {
    for cidr in ["x", "10.0.0.1", "10.0.0.1/33", "10.0.0.1/32 trust", "all"] {
        assert!(
            member_hba_block(Some(&logins(&[cidr], &["chelabase-orchestrator"])), true).is_err(),
            "{cidr}"
        );
    }
    for cns in [
        vec![],
        vec!["a b"],
        vec!["a#b"],
        vec![""],
        vec!["-x"],
        vec!["x/y"],
    ] {
        assert!(
            member_ident_lines(Some(&logins(&[], &cns))).is_err(),
            "{cns:?}"
        );
    }
}

#[test]
fn ident_lines_map_each_cn_to_the_member_roles() {
    let ml = logins(&[], &["chelabase-orchestrator", "chelabase-realtime"]);
    assert_eq!(
        member_ident_lines(Some(&ml)).unwrap(),
        "chelabase_member\tchelabase-orchestrator\t/^cb_m_[0-9a-f]{32}$\n\
chelabase_member\tchelabase-realtime\t/^cb_m_[0-9a-f]{32}$\n"
    );
    assert_eq!(member_ident_lines(None).unwrap(), "");
}

#[test]
fn update_pg_hba_puts_the_block_first_and_md5_last() {
    let dir = Path::new("./tests/tmp/round3_hba");
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let sample = "local   all             all                                     trust\n\
host    all             all             127.0.0.1/32            trust\n";
    std::fs::write(dir.join("pg_hba.conf"), sample).unwrap();
    std::fs::write(dir.join("PG_VERSION"), "17\n").unwrap();
    let ml = logins(&["10.213.4.10/32"], &["chelabase-orchestrator"]);
    update_pg_hba(dir, None, Some(&ml), true).unwrap();
    update_pg_hba(dir, None, Some(&ml), true).unwrap();
    let text = std::fs::read_to_string(dir.join("pg_hba.conf")).unwrap();
    let block = member_hba_block(Some(&ml), true).unwrap();
    assert!(text.starts_with(&block), "{text}");
    assert_eq!(text.matches(HEAD.trim_end()).count(), 1, "once");
    assert!(text[block.len()..].contains("127.0.0.1/32            trust"));
    assert!(
        text.trim_end().ends_with("host\tall\t\tall\t\tall\t\tmd5"),
        "{text}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tls_lines_carry_the_ca_whenever_tls_is_on() {
    let tls = |ca: Option<&str>| TlsConfig {
        key_path: "/var/db/chelabase/tls/server.key".into(),
        cert_path: "/var/db/chelabase/tls/server.crt".into(),
        ca_path: ca.map(str::to_string),
    };
    assert_eq!(
        tls_conf_lines(&tls(Some("/var/db/chelabase/tls/ca.crt"))),
        "ssl = on\nssl_cert_file = 'server.crt'\nssl_key_file = 'server.key'\nssl_ca_file = '/var/db/chelabase/tls/ca.crt'\n"
    );
    assert_eq!(
        tls_conf_lines(&tls(None)),
        "ssl = on\nssl_cert_file = 'server.crt'\nssl_key_file = 'server.key'\n"
    );
}

fn openssl_pair(dir: &Path) -> (String, String, String) {
    let run = |args: &[&str]| {
        let out = std::process::Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        "k.pem",
        "-out",
        "c.pem",
        "-days",
        "1",
        "-subj",
        "/CN=t",
    ]);
    run(&["ec", "-in", "k.pem", "-out", "k_sec1.pem"]);
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap();
    (read("k.pem"), read("k_sec1.pem"), read("c.pem"))
}

#[test]
fn both_key_forms_are_read_and_a_wrong_key_is_not() {
    let dir = Path::new("./tests/tmp/round3_keys");
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let (pkcs8, sec1, cert) = openssl_pair(dir);
    assert!(pkcs8.starts_with("-----BEGIN PRIVATE KEY-----"));
    verify_key_cert(&pkcs8, &cert).unwrap();
    verify_key_cert(&sec1, &cert).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let (other, _, _) = openssl_pair(dir);
    assert!(verify_key_cert(&other, &cert).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_certificate_change_rewrites_the_files_and_reloads_once() {
    let dir = Path::new("./tests/tmp/round3_reload");
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir.join("pgdata")).unwrap();
    let (key, _, cert) = openssl_pair(dir);
    std::fs::write(dir.join("server.key"), &key).unwrap();
    std::fs::write(dir.join("server.crt"), &cert).unwrap();
    let tls = TlsConfig {
        key_path: dir.join("server.key").to_string_lossy().into(),
        cert_path: dir.join("server.crt").to_string_lossy().into(),
        ca_path: None,
    };
    let mut reloads = 0;
    reload_tls_files(&dir.join("pgdata"), &tls, || {
        reloads += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(reloads, 1);
    assert_eq!(
        std::fs::read_to_string(dir.join("pgdata/server.crt")).unwrap(),
        cert
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.join("pgdata/server.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn migration_kinds_follow_the_files() {
    use MigrationKind::*;
    let kinds = migration_kinds();
    assert_eq!(
        kinds,
        vec![
            FailClosed, FailOpen, FailClosed, FailClosed, Skip, Skip, Skip, Skip, Skip, FailClosed,
            FailClosed, FailClosed
        ]
    );
    let files = [
        include_str!("../src/migrations/0001-add_bypass_rls_to_privileged_role.sql"),
        include_str!("../src/migrations/0002-alter_roles.sql"),
        include_str!("../src/migrations/0003-grant_pg_create_subscription_to_privileged_role.sql"),
        include_str!("../src/migrations/0004-grant_pg_monitor_to_privileged_role.sql"),
        include_str!("../src/migrations/0005-grant_all_on_tables_to_privileged_role.sql"),
        include_str!("../src/migrations/0006-grant_all_on_sequences_to_privileged_role.sql"),
        include_str!(
            "../src/migrations/0007-grant_all_on_tables_with_grant_option_to_privileged_role.sql"
        ),
        include_str!(
            "../src/migrations/0008-grant_all_on_sequences_with_grant_option_to_privileged_role.sql"
        ),
        include_str!("../src/migrations/0009-revoke_replication_for_previously_allowed_roles.sql"),
        include_str!(
            "../src/migrations/0010-grant_snapshot_synchronization_funcs_to_privileged_role.sql"
        ),
        include_str!(
            "../src/migrations/0011-grant_pg_show_replication_origin_status_to_privileged_role.sql"
        ),
        include_str!("../src/migrations/0012-grant_pg_signal_backend_to_privileged_role.sql"),
    ];
    for (i, (file, kind)) in files.iter().zip(&kinds).enumerate() {
        assert_eq!(
            file.starts_with("-- SKIP"),
            *kind == Skip,
            "migration {}",
            i + 1
        );
    }
}

#[test]
fn only_a_failure_that_leaves_a_fail_open_migration_unapplied_is_fatal() {
    let kinds = migration_kinds();
    assert!(fatal_failure(&kinds, 0), "0001 fails: 0002 stays unapplied");
    assert!(fatal_failure(&kinds, 1), "0002 itself");
    for i in 2..kinds.len() {
        assert!(!fatal_failure(&kinds, i), "migration {}", i + 1);
    }
    use MigrationKind::*;
    assert!(!fatal_failure(&[FailClosed, Skip], 0));
    assert!(fatal_failure(&[Skip, FailClosed, FailOpen], 0));
    assert_eq!(
        MIGRATION_CONN_OPTIONS,
        "-c lock_timeout=5s -c statement_timeout=2min"
    );
}

// ---------------------------------------------------------------------------
// F3 (fork round 3, final fix round)
// ---------------------------------------------------------------------------

const MD5: &str = "host\tall\t\tall\t\tall\t\tmd5\n";
const ORCH: &str = "chelabase-orchestrator";

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

/// E-m3: a changed `member_logins` replaces the text between the markers; the
/// rest of the file (hand edits before and after the block included) is kept
/// byte for byte; N entries to 0 and back; idempotent.
#[test]
fn update_pg_hba_replaces_the_block_between_the_markers() {
    let dir = pgdata("f3_hba_replace", Some("17"));
    let hba = dir.join("pg_hba.conf");
    let before = "# edited by hand, above the block\n";
    let after = "local   all   all   trust\n# edited by hand, below the block\n\t \n";
    let old = logins(&["10.213.4.10/32", "10.213.4.11/32"], &[ORCH]);
    std::fs::write(
        &hba,
        format!(
            "{before}{}{after}{MD5}",
            member_hba_block(Some(&old), true).unwrap()
        ),
    )
    .unwrap();
    let expect = |ml: Option<&MemberLogins>| {
        format!(
            "{before}{}{after}{MD5}",
            member_hba_block(ml, true).unwrap()
        )
    };

    let new = logins(&["10.213.4.12/32", "fd00::12/128"], &[ORCH]);
    update_pg_hba(&dir, None, Some(&new), true).unwrap();
    assert_eq!(
        read(&hba),
        expect(Some(&new)),
        "the new list replaces the old"
    );
    update_pg_hba(&dir, None, Some(&new), true).unwrap();
    assert_eq!(read(&hba), expect(Some(&new)), "idempotent");

    let none = logins(&[], &[ORCH]);
    update_pg_hba(&dir, None, Some(&none), true).unwrap();
    assert_eq!(
        read(&hba),
        expect(Some(&none)),
        "0 entries: the address rule is off"
    );
    assert!(read(&hba).contains(&allow("all")));
    update_pg_hba(&dir, None, Some(&new), true).unwrap();
    assert_eq!(read(&hba), expect(Some(&new)), "and back");

    update_pg_hba(&dir, None, None, true).unwrap();
    assert_eq!(read(&hba), expect(None), "no member_logins: reject only");
    assert!(!read(&hba).contains("hostssl"));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// E-m3: a block cut short (a start marker without its end, or the markers out
/// of order) is a clear error; the file is left as it was.
#[test]
fn update_pg_hba_refuses_a_truncated_block() {
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    let block = member_hba_block(Some(&ml), true).unwrap();
    let head_only = block.replace(TAIL, "");
    let tail_only = block.replace(HEAD, "");
    let cases = [
        (
            "start marker only",
            format!("{head_only}local all all trust\n{MD5}"),
        ),
        (
            "end marker only",
            format!("{tail_only}local all all trust\n{MD5}"),
        ),
        (
            "end before start",
            format!("{TAIL}local all all trust\n{HEAD}{MD5}"),
        ),
        ("a second start inside", format!("{head_only}{block}{MD5}")),
    ];
    for (i, (what, text)) in cases.iter().enumerate() {
        let dir = pgdata(&format!("f3_hba_truncated_{i}"), Some("17"));
        let hba = dir.join("pg_hba.conf");
        std::fs::write(&hba, text).unwrap();
        let err =
            update_pg_hba(&dir, None, Some(&ml), true).expect_err(&format!("{what}: must fail"));
        assert!(
            format!("{err:#}").contains("pg_hba.conf"),
            "{what}: the error names the file: {err:#}"
        );
        assert_eq!(&read(&hba), text, "{what}: the file is untouched");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// T6 m6: below v17 Postgres refuses `map=` on a `clientcert=verify-full` line
/// (the hba.c change is v17 only), so the block holds only the reject lines.
/// A missing or unreadable `PG_VERSION` fails closed the same way.
#[test]
fn below_v17_the_block_only_rejects() {
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    for (i, version) in [Some("16"), Some("15"), Some("14"), None, Some("garbage")]
        .iter()
        .enumerate()
    {
        let dir = pgdata(&format!("f3_hba_version_{i}"), *version);
        update_pg_hba(&dir, None, Some(&ml), true).unwrap();
        let text = read(&dir.join("pg_hba.conf"));
        assert!(
            text.starts_with(&format!("{HEAD}{REJECT}{TAIL}")),
            "PG_VERSION {version:?}: reject lines only:\n{text}"
        );
        assert!(!text.contains("hostssl"), "PG_VERSION {version:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
    let dir = pgdata("f3_hba_version_17", Some("17"));
    update_pg_hba(&dir, None, Some(&ml), true).unwrap();
    assert!(
        read(&dir.join("pg_hba.conf")).starts_with(&member_hba_block(Some(&ml), true).unwrap())
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

fn ident_map_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| l.starts_with("chelabase_member"))
        .collect()
}

/// E-m3: pg_ident's member lines follow `client_cns` (a CN dropped from the list
/// stops mapping); other lines are kept; idempotent.
#[test]
fn update_pg_ident_replaces_the_member_lines() {
    let dir = pgdata("f3_ident_replace", Some("17"));
    let ident = dir.join("pg_ident.conf");
    let mine = "# edited by hand\nmymap\tbob\tbob\n";
    std::fs::write(&ident, mine).unwrap();
    let line = |cn: &str| format!("chelabase_member\t{cn}\t/^cb_m_[0-9a-f]{{32}}$");

    update_pg_ident(&dir, None, Some(&logins(&[], &["cn-a", "cn-b"]))).unwrap();
    update_pg_ident(&dir, None, Some(&logins(&[], &["cn-b", "cn-c"]))).unwrap();
    let text = read(&ident);
    assert_eq!(
        ident_map_lines(&text),
        vec![line("cn-b"), line("cn-c")],
        "cn-a is gone:\n{text}"
    );
    assert!(text.contains(mine), "other lines kept:\n{text}");
    update_pg_ident(&dir, None, Some(&logins(&[], &["cn-b", "cn-c"]))).unwrap();
    assert_eq!(read(&ident), text, "idempotent");

    update_pg_ident(&dir, None, None).unwrap();
    let text = read(&ident);
    assert!(
        ident_map_lines(&text).is_empty(),
        "no member_logins:\n{text}"
    );
    assert!(text.contains(mine), "other lines kept:\n{text}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// openssl in `dir`, panicking with its stderr on failure.
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

/// A P-256 CA `<name>.crt`/`<name>.key`. Every CA here has the same subject, as
/// a regenerated CA does, so only the signature tells them apart.
fn make_ca(dir: &Path, name: &str) {
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
            "/CN=chelabase-compute-ca",
        ],
    );
}

/// A server pair `<name>.crt`/`<name>.key` (PKCS#8) signed by CA `ca`.
fn make_server(dir: &Path, name: &str, ca: &str) {
    openssl(
        dir,
        &[
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-subj",
            "/CN=compute",
        ],
    );
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{ca}.crt"),
            "-CAkey",
            &format!("{ca}.key"),
            "-CAcreateserial",
            "-days",
            "2",
            "-out",
            &format!("{name}.crt"),
        ],
    );
}

fn tls_in(dir: &Path, ca: Option<&str>) -> TlsConfig {
    TlsConfig {
        key_path: dir.join("server.key").to_string_lossy().into(),
        cert_path: dir.join("server.crt").to_string_lossy().into(),
        ca_path: ca.map(|f| dir.join(f).to_string_lossy().into()),
    }
}

/// Installs pair `name` as the compute's mounted server.key/server.crt.
fn mount(dir: &Path, name: &str) {
    std::fs::copy(dir.join(format!("{name}.key")), dir.join("server.key")).unwrap();
    std::fs::copy(dir.join(format!("{name}.crt")), dir.join("server.crt")).unwrap();
}

/// T6 m1: with `ca_path` set, a server certificate that doesn't chain to the CA
/// file (a CA rotation seen half-done, a half-written ca.crt, a missing one)
/// reloads nothing and writes nothing; the caller retries at the next poll.
#[test]
fn reload_checks_the_server_certificate_against_the_ca() {
    let dir = pgdata("f3_tls_ca", None);
    let pg = dir.join("pgdata");
    std::fs::create_dir_all(&pg).unwrap();
    make_ca(&dir, "ca_a");
    make_ca(&dir, "ca_b");
    make_server(&dir, "s1", "ca_a");
    make_server(&dir, "s2", "ca_b");
    let ca_a = read(&dir.join("ca_a.crt"));
    let ca_b = read(&dir.join("ca_b.crt"));
    std::fs::write(dir.join("ca.crt"), &ca_a).unwrap();
    let tls = tls_in(&dir, Some("ca.crt"));
    let reloads = std::cell::Cell::new(0);
    let reload = || {
        reloads.set(reloads.get() + 1);
        Ok::<(), anyhow::Error>(())
    };

    // Signed by another CA with the same name.
    mount(&dir, "s2");
    assert!(
        reload_tls_files(&pg, &tls, reload).is_err(),
        "s2 doesn't chain to ca_a"
    );
    assert_eq!(reloads.get(), 0);
    assert!(!pg.join("server.crt").exists() && !pg.join("server.key").exists());

    // The CA bundle names it: loaded.
    std::fs::write(dir.join("ca.crt"), format!("{ca_a}{ca_b}")).unwrap();
    reload_tls_files(&pg, &tls, reload).unwrap();
    assert_eq!(reloads.get(), 1);
    assert_eq!(read(&pg.join("server.crt")), read(&dir.join("s2.crt")));

    // A half-written CA file, then a missing one.
    mount(&dir, "s1");
    std::fs::write(dir.join("ca.crt"), &ca_a[..ca_a.len() / 2]).unwrap();
    assert!(
        reload_tls_files(&pg, &tls, reload).is_err(),
        "half-written ca.crt"
    );
    std::fs::remove_file(dir.join("ca.crt")).unwrap();
    assert!(
        reload_tls_files(&pg, &tls, reload).is_err(),
        "missing ca.crt"
    );
    assert_eq!(reloads.get(), 1);
    assert_eq!(
        read(&pg.join("server.crt")),
        read(&dir.join("s2.crt")),
        "untouched"
    );

    // Whole again.
    std::fs::write(dir.join("ca.crt"), &ca_a).unwrap();
    reload_tls_files(&pg, &tls, reload).unwrap();
    assert_eq!(reloads.get(), 2);
    assert_eq!(read(&pg.join("server.crt")), read(&dir.join("s1.crt")));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A key and certificate from different generations (a renewal seen
/// half-written) reload nothing and write nothing.
#[test]
fn key_and_certificate_from_different_generations_reload_nothing() {
    let dir = pgdata("f3_tls_generations", None);
    let pg = dir.join("pgdata");
    std::fs::create_dir_all(&pg).unwrap();
    make_ca(&dir, "ca");
    make_server(&dir, "s1", "ca");
    make_server(&dir, "s2", "ca");
    std::fs::copy(dir.join("s1.key"), dir.join("server.key")).unwrap();
    std::fs::copy(dir.join("s2.crt"), dir.join("server.crt")).unwrap();
    for ca in [None, Some("ca.crt")] {
        let mut reloads = 0;
        let result = reload_tls_files(&pg, &tls_in(&dir, ca), || {
            reloads += 1;
            Ok(())
        });
        assert!(result.is_err(), "ca {ca:?}");
        assert_eq!(reloads, 0, "ca {ca:?}");
        assert!(!pg.join("server.crt").exists() && !pg.join("server.key").exists());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// T6 m3: the watcher and a reconfigure copying the files at once never collide
/// on a temporary file, and leave only the two files behind.
#[test]
fn concurrent_reloads_never_collide() {
    let dir = pgdata("f3_tls_concurrent", None);
    let pg = dir.join("pgdata");
    std::fs::create_dir_all(&pg).unwrap();
    make_ca(&dir, "ca");
    make_server(&dir, "s1", "ca");
    mount(&dir, "s1");
    let tls = tls_in(&dir, Some("ca.crt"));
    let errors: Vec<String> = std::thread::scope(|s| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    let mut errors = Vec::new();
                    for _ in 0..100 {
                        if let Err(e) = reload_tls_files(&pg, &tls, || Ok(())) {
                            errors.push(format!("{e:#}"));
                        }
                    }
                    errors
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect()
    });
    assert!(
        errors.is_empty(),
        "{} of 800 reloads failed, e.g. {:?}",
        errors.len(),
        errors.first()
    );
    let mut left: Vec<String> = std::fs::read_dir(&pg)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, vec!["server.crt", "server.key"]);
    assert_eq!(read(&pg.join("server.crt")), read(&dir.join("s1.crt")));
    assert_eq!(read(&pg.join("server.key")), read(&dir.join("s1.key")));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// T6 m4: a failure before any migration ran names no migration.
#[test]
fn a_failure_before_the_migrations_names_no_migration() {
    let before = MigrationFailure::before_migrations(anyhow::anyhow!("connection refused"));
    assert_eq!(
        before.to_string(),
        "migrations could not run: connection refused"
    );
    let during = MigrationFailure {
        index: 2,
        in_migration: true,
        error: anyhow::anyhow!("boom"),
    };
    assert_eq!(during.to_string(), "migration 3 failed: boom");
}
