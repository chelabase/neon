//! Final fix round (F1): edge cases beyond the RED set (the coder's own tests).
//!
//! - `--control-plane-token-file`: a FIFO at the path fails the startup at once
//!   (never blocks it); a symlink to a regular file is read; an oversized or
//!   non-UTF-8 file is refused; an empty `--control-plane-token` beside the file
//!   is no conflict; errors never carry the content.
//! - `--redis-plain-password-file`: a FIFO is refused at once, too.
//! - `--redis-plain` without a password file is still checked for its scheme.

use std::time::Duration;

use camino::Utf8Path;
use clap::Parser;

use super::{ProxyCliArgs, control_plane_token, plain_redis_connection_info};

const FLAG: &str = "control-plane-token-file";
const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.eyJmMSI6ImVkZ2UifQ.EdgeNeedle";

fn args(file: &Utf8Path, extra: &[&str]) -> ProxyCliArgs {
    let mut argv: Vec<String> = vec!["proxy".into(), format!("--{FLAG}={file}")];
    argv.extend(extra.iter().map(|s| s.to_string()));
    ProxyCliArgs::parse_from(argv)
}

fn mkfifo(path: &Utf8Path) {
    let made = std::process::Command::new("mkfifo")
        .arg(path.as_str())
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo failed");
}

/// Runs `f` on a thread and fails when it doesn't return within 10 s (a
/// blocked open of a FIFO), unblocking the FIFO afterwards.
fn within_10s<T: Send + 'static>(fifo: &Utf8Path, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        drop(tx.send(f()));
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(v) => v,
        Err(_) => {
            let fifo = fifo.to_owned();
            std::thread::spawn(move || drop(std::fs::OpenOptions::new().write(true).open(fifo)));
            panic!("reading the secret file blocked on a FIFO");
        }
    }
}

#[test]
fn a_fifo_control_plane_token_file_fails_at_once() {
    let dir = camino_tempfile::tempdir().unwrap();
    let fifo = dir.path().join("proxy-api.token");
    mkfifo(&fifo);
    let a = args(&fifo, &[]);
    let e = within_10s(&fifo, move || control_plane_token(&a)).unwrap_err();
    assert!(format!("{e:#}").contains(FLAG), "{e:#}");
    assert!(format!("{e:#}").contains("regular file"), "{e:#}");
}

#[test]
fn a_fifo_redis_password_file_fails_at_once() {
    let dir = camino_tempfile::tempdir().unwrap();
    let fifo = dir.path().join("valkey.password");
    mkfifo(&fifo);
    let path = fifo.clone();
    let e = within_10s(&fifo, move || {
        plain_redis_connection_info("redis://proxy@valkey:6379", Some(&path)).map(|_| ())
    })
    .unwrap_err();
    assert!(
        format!("{e:#}").contains("redis-plain-password-file"),
        "{e:#}"
    );
}

#[test]
fn a_symlink_to_a_regular_token_file_is_read() {
    let dir = camino_tempfile::tempdir().unwrap();
    let target = dir.path().join("real.token");
    std::fs::write(&target, format!("{TOKEN}\n")).unwrap();
    let link = dir.path().join("proxy-api.token");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(&*control_plane_token(&args(&link, &[])).unwrap(), TOKEN);
}

#[test]
fn an_oversized_or_non_utf8_token_file_is_refused() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy-api.token");
    for (why, content) in [
        ("oversized", vec![b'a'; 64 * 1024 + 1]),
        ("not UTF-8", b"EdgeNeedle\xff\n".to_vec()),
    ] {
        std::fs::write(&file, &content).unwrap();
        let e = control_plane_token(&args(&file, &[])).expect_err(why);
        let text = format!("{e:#} {e:?}");
        assert!(text.contains(FLAG), "{why}: {text}");
        assert!(!text.contains("EdgeNeedle"), "{why}: {text}");
    }
    // Exactly the limit is still read.
    std::fs::write(&file, vec![b'a'; 64 * 1024]).unwrap();
    assert_eq!(
        control_plane_token(&args(&file, &[])).unwrap().len(),
        64 * 1024
    );
}

#[test]
fn an_empty_token_flag_beside_the_file_is_no_conflict() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy-api.token");
    std::fs::write(&file, format!("{TOKEN}\n")).unwrap();
    let token = control_plane_token(&args(&file, &["--control-plane-token="])).unwrap();
    assert_eq!(&*token, TOKEN);
}

#[test]
fn the_scheme_is_checked_without_a_password_file() {
    let e = plain_redis_connection_info("unix:///run/valkey.sock", None).unwrap_err();
    assert!(format!("{e:#}").contains("--redis-plain"), "{e:#}");
    assert!(!format!("{e:#}").contains("valkey.sock"), "{e:#}");
}
