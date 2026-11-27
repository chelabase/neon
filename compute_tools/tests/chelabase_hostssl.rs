//! chelabase#248: a compute accepts a non-loopback password login only over TLS.
//!
//! Invariant, checked over every combination `plan_pg_hba` sees (major 14 or 17,
//! TLS on or off, with or without member, realtime and databricks settings,
//! starting from the basebackup's file with or without the old plaintext
//! catch-all, run once and again): in the written `pg_hba.conf`, every `host`
//! line (TCP with or without TLS) for a non-loopback address is a `reject`
//! line; the password catch-all is the one `hostssl all all all md5` line; the
//! basebackup's loopback and Unix-socket lines are kept as they were, before
//! the catch-all.

use std::fs;
use std::path::{Path, PathBuf};

use compute_api::spec::MemberLogins;
use compute_tools::spec::update_pg_hba;

/// What the pageserver's basebackup ships as `pg_hba.conf`.
const BASEBACKUP: &str = include_str!("../../libs/postgres_ffi/samples/pg_hba.conf");
/// The catch-all compute_ctl wrote before chelabase#248 (plaintext allowed).
const PLAIN_CATCH_ALL: &str = "host\tall\t\tall\t\tall\t\tmd5";
const CATCH_ALL: &str = "hostssl\tall\t\tall\t\tall\t\tmd5";

/// Loopback: anything in 127.0.0.0/8 (pooled endpoints' 127.0.0.2 block too) or ::1.
fn is_loopback(address: &str) -> bool {
    address.starts_with("127.") || address == "::1/128" || address == "::1"
}

fn pgdata(name: &str, major: u32) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("PG_VERSION"), format!("{major}\n")).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn logins(cidrs: &[&str], cns: &[&str]) -> MemberLogins {
    MemberLogins {
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        client_cns: cns.iter().map(|s| s.to_string()).collect(),
    }
}

/// The non-comment lines of `hba`, split into fields.
fn rules(hba: &str) -> Vec<Vec<&str>> {
    hba.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| !f.is_empty())
        .collect()
}

fn check_invariant(hba: &str, case: &str) {
    let rules = rules(hba);
    for f in &rules {
        match f[0] {
            "local" | "include_if_exists" | "hostssl" => {}
            // host, hostnossl, hostgssenc, hostnogssenc: not TLS-only.
            t if t.starts_with("host") => {
                // TYPE DATABASE USER ADDRESS METHOD [OPTIONS]
                assert!(f.len() >= 5, "{case}: short line {f:?}");
                assert!(
                    is_loopback(f[3]) || f[4] == "reject",
                    "{case}: a non-TLS non-loopback rule {f:?} in\n{hba}"
                );
            }
            other => panic!("{case}: unexpected line type {other:?} in {f:?}"),
        }
    }
    let catch_all: Vec<usize> = hba
        .lines()
        .enumerate()
        .filter(|(_, l)| *l == CATCH_ALL)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        catch_all.len(),
        1,
        "{case}: one hostssl catch-all in\n{hba}"
    );
    assert!(
        !hba.lines().any(|l| l == PLAIN_CATCH_ALL),
        "{case}: the plaintext catch-all is still there:\n{hba}"
    );
    let sample_at = hba
        .find(BASEBACKUP)
        .unwrap_or_else(|| panic!("{case}: the basebackup lines aren't kept as is:\n{hba}"));
    let sample_end_line = hba[..sample_at + BASEBACKUP.len()].lines().count();
    assert!(
        catch_all[0] >= sample_end_line,
        "{case}: the catch-all comes before the loopback lines:\n{hba}"
    );
}

#[test]
fn non_loopback_password_logins_need_tls() {
    let member = logins(&["10.213.4.10/32"], &["chelabase-orchestrator"]);
    let realtime = logins(&["10.213.4.12/32"], &["chelabase-realtime"]);
    let databricks = "/databricks/pg_hba.conf".to_string();
    let mut n = 0;
    for major in [14, 17] {
        for tls in [false, true] {
            for member in [None, Some(&member)] {
                for realtime in [None, Some(&realtime)] {
                    for databricks in [None, Some(&databricks)] {
                        for legacy in [false, true] {
                            let case = format!(
                                "major {major}, tls {tls}, member {}, realtime {}, databricks {}, legacy {legacy}",
                                member.is_some(),
                                realtime.is_some(),
                                databricks.is_some()
                            );
                            let dir = pgdata(&format!("hostssl_{n}"), major);
                            n += 1;
                            let start = if legacy {
                                format!("{BASEBACKUP}{PLAIN_CATCH_ALL}\n")
                            } else {
                                BASEBACKUP.to_string()
                            };
                            fs::write(dir.join("pg_hba.conf"), start).unwrap();
                            update_pg_hba(&dir, databricks, member, realtime, tls).unwrap();
                            let once = fs::read_to_string(dir.join("pg_hba.conf")).unwrap();
                            check_invariant(&once, &case);
                            update_pg_hba(&dir, databricks, member, realtime, tls).unwrap();
                            let twice = fs::read_to_string(dir.join("pg_hba.conf")).unwrap();
                            assert_eq!(once, twice, "{case}: a second run changes the file");
                            fs::remove_dir_all(&dir).unwrap();
                        }
                    }
                }
            }
        }
    }
}

/// The old plaintext catch-all is replaced where it stands (a reconfigure of a
/// compute whose file has it), not left above a new `hostssl` line, where it
/// would still match first.
#[test]
fn the_plaintext_catch_all_is_replaced_in_place() {
    let dir = pgdata("hostssl_in_place", 17);
    let after = "host\tall\t\tall\t\t10.0.0.0/8\t\treject\n";
    fs::write(
        dir.join("pg_hba.conf"),
        format!("{BASEBACKUP}{PLAIN_CATCH_ALL}\n{after}"),
    )
    .unwrap();
    update_pg_hba(&dir, None, None, None, true).unwrap();
    let hba = fs::read_to_string(dir.join("pg_hba.conf")).unwrap();
    assert!(
        hba.ends_with(&format!("{BASEBACKUP}{CATCH_ALL}\n{after}")),
        "got:\n{hba}"
    );
    fs::remove_dir_all(&dir).unwrap();
}
