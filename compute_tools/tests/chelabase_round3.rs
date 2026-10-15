//! Round 3: the member pg_hba block and pg_ident lines, TLS lines and keys, migration kinds.

use std::path::Path;

use compute_api::responses::TlsConfig;
use compute_api::spec::MemberLogins;
use compute_tools::config::tls_conf_lines;
use compute_tools::migration::{MIGRATION_CONN_OPTIONS, MigrationKind, fatal_failure};
use compute_tools::spec::{member_hba_block, member_ident_lines, migration_kinds, update_pg_hba};
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
