//! K8: `proxy --redis-plain-password-file` (spec S11, RT4-13) and
//! `proxy --compute-ctl-token-file` for the testing `Local` backend.
//!
//! Pinned (new):
//! - `ProxyCliArgs.redis_plain_password_file: Option<Utf8PathBuf>`;
//! - `ProxyCliArgs.compute_ctl_token_file: Option<Utf8PathBuf>` (no default);
//! - `fn plain_redis_connection_info(url: &str, password_file: Option<&Utf8Path>)
//!   -> anyhow::Result<redis::ConnectionInfo>`: the one place the plain URL and
//!   the password file become connection info; `configure_redis` calls it for
//!   `--redis-auth-type=plain`. The password is set through the `url` crate's
//!   `set_password` (percent-encoding), never spliced into the URL text.

use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use futures::future::Either;

use super::{ProxyCliArgs, build_auth_backend, configure_redis, plain_redis_connection_info};
use crate::auth::Backend;

const URL: &str = "redis://proxy@valkey:6379";
const PW: &str = "S3cretPassw0rdXYZ";
const FLAG: &str = "redis-plain-password-file";

fn write_pw(dir: &camino_tempfile::Utf8TempDir, content: &[u8]) -> Utf8PathBuf {
    let path = dir.path().join("valkey-proxy.password");
    std::fs::write(&path, content).unwrap();
    path
}

fn err_texts(e: &anyhow::Error) -> Vec<String> {
    vec![format!("{e}"), format!("{e:#}"), format!("{e:?}")]
}

fn assert_clean(e: &anyhow::Error, secrets: &[&str]) {
    for t in err_texts(e) {
        for s in secrets {
            assert!(!t.contains(s), "error text leaks {s:?}: {t}");
        }
    }
}

// ---- --redis-plain-password-file -------------------------------------------------

#[test]
fn the_flags_parse() {
    let args = ProxyCliArgs::parse_from([
        "proxy",
        "--redis-auth-type=plain",
        "--redis-plain=redis://proxy@valkey:6379",
        "--redis-plain-password-file=/run/valkey-proxy.password",
    ]);
    assert_eq!(
        args.redis_plain_password_file
            .as_deref()
            .map(|p| p.as_str()),
        Some("/run/valkey-proxy.password")
    );
    let args = ProxyCliArgs::parse_from(["proxy"]);
    assert!(args.redis_plain_password_file.is_none());
}

#[test]
fn url_plus_file_gives_user_host_and_password() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = write_pw(&dir, format!("{PW}\n").as_bytes());
    let info = plain_redis_connection_info(URL, Some(&file)).unwrap();
    assert_eq!(info.redis.username.as_deref(), Some("proxy"));
    assert_eq!(info.redis.password.as_deref(), Some(PW));
    match info.addr {
        redis::ConnectionAddr::Tcp(host, port) => {
            assert_eq!(host, "valkey");
            assert_eq!(port, 6379);
        }
        other => panic!("unexpected address {other:?}"),
    }
}

#[test]
fn one_trailing_newline_is_trimmed_and_not_required() {
    let dir = camino_tempfile::tempdir().unwrap();
    for (content, want) in [
        ("pw\n", "pw"),
        ("pw", "pw"),
        // Only one newline is trimmed.
        ("pw\n\n", "pw\n"),
    ] {
        let file = write_pw(&dir, content.as_bytes());
        let info = plain_redis_connection_info(URL, Some(&file)).unwrap();
        assert_eq!(info.redis.password.as_deref(), Some(want), "{content:?}");
    }
}

#[test]
fn the_url_form_without_a_file_still_works() {
    let info = plain_redis_connection_info("redis://proxy:oldstyle@valkey:6379", None).unwrap();
    assert_eq!(info.redis.username.as_deref(), Some("proxy"));
    assert_eq!(info.redis.password.as_deref(), Some("oldstyle"));
    let info = plain_redis_connection_info(URL, None).unwrap();
    assert_eq!(info.redis.password, None);
}

#[test]
fn reserved_characters_are_percent_encoded_not_spliced() {
    let dir = camino_tempfile::tempdir().unwrap();
    for pw in [
        "p@ss",
        "a:b",
        "a/b",
        "100%",
        "%41",
        "%zz",
        "@:/%",
        "p@ss:w/rd%41",
        "a#b",
        "a?b=c",
        "a b",
        "a\\b",
        "[::1]",
        "x@evil.example:1/0",
        "pa\u{e9}ss",
        "a+b&c=d",
    ] {
        let file = write_pw(&dir, format!("{pw}\n").as_bytes());
        let info = plain_redis_connection_info(URL, Some(&file)).unwrap();
        assert_eq!(info.redis.password.as_deref(), Some(pw), "password {pw:?}");
        // The host, port and user come from the URL alone: a password can't redirect it.
        assert_eq!(info.redis.username.as_deref(), Some("proxy"), "{pw:?}");
        match info.addr {
            redis::ConnectionAddr::Tcp(host, port) => {
                assert_eq!((host.as_str(), port), ("valkey", 6379), "{pw:?}");
            }
            other => panic!("unexpected address {other:?} for {pw:?}"),
        }
    }
}

#[test]
fn the_database_and_scheme_of_the_url_survive() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = write_pw(&dir, b"p@ss\n");
    let info = plain_redis_connection_info("redis://proxy@valkey:6379/2", Some(&file)).unwrap();
    assert_eq!(info.redis.db, 2);
    assert_eq!(info.redis.password.as_deref(), Some("p@ss"));
    let info = plain_redis_connection_info("rediss://proxy@valkey:6380", Some(&file)).unwrap();
    assert!(matches!(
        info.addr,
        redis::ConnectionAddr::TcpTls { ref host, port, .. } if host == "valkey" && port == 6380
    ));
    // No user in the URL: the password alone.
    let info = plain_redis_connection_info("redis://valkey:6379", Some(&file)).unwrap();
    assert_eq!(info.redis.username, None);
    assert_eq!(info.redis.password.as_deref(), Some("p@ss"));
}

#[test]
fn an_empty_file_fails_closed() {
    let dir = camino_tempfile::tempdir().unwrap();
    for content in [&b""[..], &b"\n"[..]] {
        let file = write_pw(&dir, content);
        let e = plain_redis_connection_info(URL, Some(&file)).unwrap_err();
        assert!(
            format!("{e:#}").contains(FLAG),
            "the error must name the flag: {e:#}"
        );
    }
}

#[test]
fn a_missing_file_fails_closed() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("nope");
    let e = plain_redis_connection_info(URL, Some(&file)).unwrap_err();
    assert!(
        format!("{e:#}").contains(FLAG),
        "the error must name the flag: {e:#}"
    );
    // A directory is not a password file either.
    let e = plain_redis_connection_info(URL, Some(dir.path())).unwrap_err();
    assert!(format!("{e:#}").contains(FLAG), "{e:#}");
}

#[test]
fn a_url_that_already_has_a_password_fails_closed_with_a_file() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = write_pw(&dir, format!("{PW}\n").as_bytes());
    let url_pw = "UrlPassw0rdABC";
    let e =
        plain_redis_connection_info(&format!("redis://proxy:{url_pw}@valkey:6379"), Some(&file))
            .unwrap_err();
    assert!(
        format!("{e:#}").contains(FLAG),
        "the error must name the flag: {e:#}"
    );
    assert_clean(&e, &[PW, url_pw]);
}

#[test]
fn errors_never_contain_a_password() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = write_pw(&dir, format!("{PW}\n").as_bytes());
    // An unusable URL together with a good file: the file's password stays out of the error.
    for bad in [
        "not a url",
        "http://valkey:6379",
        "redis://",
        "",
        "redis://proxy@valkey:99999",
    ] {
        let e = plain_redis_connection_info(bad, Some(&file))
            .expect_err(&format!("{bad:?} must be refused"));
        assert_clean(&e, &[PW]);
    }
    // A password embedded in a refused URL is not echoed either.
    let e = plain_redis_connection_info("http://proxy:UrlPassw0rdABC@valkey:6379", None)
        .expect_err("not a redis URL");
    assert_clean(&e, &["UrlPassw0rdABC"]);
}

// ---- configure_redis, as the flags reach it -------------------------------------

fn plain_args(url: Option<&str>, file: Option<&Utf8Path>) -> ProxyCliArgs {
    let mut argv: Vec<String> = vec!["proxy".into(), "--redis-auth-type=plain".into()];
    if let Some(url) = url {
        argv.push(format!("--redis-plain={url}"));
    }
    if let Some(file) = file {
        argv.push(format!("--redis-plain-password-file={file}"));
    }
    ProxyCliArgs::parse_from(argv)
}

#[tokio::test]
#[tracing_test::traced_test]
async fn configure_redis_reads_the_file_and_logs_nothing_secret() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = write_pw(&dir, format!("{PW}\n").as_bytes());
    let client = configure_redis(&plain_args(Some(URL), Some(&file)))
        .await
        .unwrap();
    assert!(client.is_some());
    assert!(!logs_contain(PW), "the password appeared in a log line");
}

#[tokio::test]
async fn configure_redis_fails_closed() {
    let dir = camino_tempfile::tempdir().unwrap();
    let empty = write_pw(&dir, b"");
    let missing = dir.path().join("missing");
    let good = write_pw(&dir, format!("{PW}\n").as_bytes());

    for (why, args) in [
        ("empty file", plain_args(Some(URL), Some(&empty))),
        ("missing file", plain_args(Some(URL), Some(&missing))),
        (
            "url with a password",
            plain_args(Some("redis://proxy:inurl@valkey:6379"), Some(&good)),
        ),
        ("file without a url", plain_args(None, Some(&good))),
    ] {
        let e = match configure_redis(&args).await {
            Ok(_) => panic!("{why}: expected a startup error"),
            Err(e) => e,
        };
        assert_clean(&e, &[PW, "inurl"]);
    }
}

// ---- --compute-ctl-token-file on the testing Local backend ------------------------

#[test]
fn the_compute_ctl_token_flag_has_no_default() {
    let args = ProxyCliArgs::parse_from(["proxy", "--auth-backend", "local"]);
    assert!(args.compute_ctl_token_file.is_none());
    let args = ProxyCliArgs::parse_from([
        "proxy",
        "--auth-backend=local",
        "--compute-ctl-token-file=/run/ctl.token",
    ]);
    assert_eq!(
        args.compute_ctl_token_file.as_deref().map(|p| p.as_str()),
        Some("/run/ctl.token")
    );
}

fn local_token_file(argv: &[&str]) -> Option<Utf8PathBuf> {
    let args = ProxyCliArgs::parse_from(argv);
    let Ok(Either::Left(Backend::Local(local))) = build_auth_backend(&args) else {
        panic!("--auth-backend local must build the Local backend");
    };
    local.compute_ctl.token_file().map(|p| p.to_path_buf())
}

#[test]
fn the_local_backend_gets_the_flag() {
    let dir = camino_tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent.token");
    // A file that doesn't exist yet is not a startup error (SP19).
    assert_eq!(
        local_token_file(&[
            "proxy",
            "--auth-backend",
            "local",
            "--compute-ctl-token-file",
            missing.as_str(),
        ]),
        Some(missing)
    );
}

#[test]
fn without_the_flag_the_local_backend_sends_no_header() {
    assert_eq!(
        local_token_file(&["proxy", "--auth-backend", "local"]),
        None
    );
}
