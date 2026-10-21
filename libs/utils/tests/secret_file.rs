//! F6: the safe secret-file reader, shared by the proxy, the storage controller and the
//! pageserver (moved from the proxy's `read_secret_file`; its cases are ported here and the
//! proxy keeps its own tests through `--control-plane-token-file` and
//! `--redis-plain-password-file`).
//!
//! Pinned:
//! - `utils::secret_file::read_secret_file(path: &Utf8Path, flag: &str) -> anyhow::Result<String>`:
//!   the file's content with one trailing `\n` trimmed, read once. The open is `O_NONBLOCK`
//!   and only a regular file is read (a symlink to one is followed), so a FIFO never blocks.
//!   An unreadable, missing, non-regular, oversized, non-UTF-8 or empty file, or a control
//!   character (`char::is_control`: a second newline and `\r` included) in the secret, is an
//!   error naming `flag` and the path, never the content.
//! - `utils::secret_file::MAX_SECRET_FILE_LEN: u64 = 64 * 1024`: the longest file read.

use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use utils::secret_file::{MAX_SECRET_FILE_LEN, read_secret_file};

const FLAG: &str = "--some-secret-file";
const NEEDLE: &str = "SecretFileNeedle";

fn write(dir: &camino_tempfile::Utf8TempDir, name: &str, content: &[u8]) -> Utf8PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn assert_clean(e: &anyhow::Error, secrets: &[&str]) {
    for t in [format!("{e}"), format!("{e:#}"), format!("{e:?}")] {
        for s in secrets {
            assert!(!t.contains(s), "error text leaks {s:?}: {t}");
        }
    }
}

fn mkfifo(path: &Utf8Path) {
    let made = std::process::Command::new("mkfifo")
        .arg(path.as_str())
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo failed");
}

/// Runs `f` on a thread and fails when it doesn't return within 10 s (a blocked open of a
/// FIFO), unblocking the FIFO afterwards.
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
fn the_limit_is_64_kib() {
    assert_eq!(MAX_SECRET_FILE_LEN, 64 * 1024);
}

#[test]
fn one_trailing_newline_is_trimmed_and_not_required() {
    let dir = camino_tempfile::tempdir().unwrap();
    for (content, want) in [
        (format!("{NEEDLE}\n"), NEEDLE),
        (NEEDLE.to_string(), NEEDLE),
    ] {
        let file = write(&dir, "s", content.as_bytes());
        assert_eq!(read_secret_file(&file, FLAG).unwrap(), want, "{content:?}");
    }
}

#[test]
fn the_content_comes_back_verbatim() {
    let dir = camino_tempfile::tempdir().unwrap();
    for secret in [
        "p@ss",
        "a:b",
        "a/b",
        "100%",
        "%41",
        "@:/%",
        "a#b",
        "a?b=c",
        "a b",
        "a\\b",
        "[::1]",
        "'quoted\"",
        "$(echo no)",
        "pa\u{e9}ss",
        "a+b&c=d",
        "eyJhbGciOiJFZERTQSJ9.eyJzY29wZSI6InBhZ2VzZXJ2ZXJhcGkifQ.c2ln",
    ] {
        let file = write(&dir, "s", format!("{secret}\n").as_bytes());
        assert_eq!(read_secret_file(&file, FLAG).unwrap(), secret, "{secret:?}");
    }
}

#[test]
fn an_empty_file_fails_closed() {
    let dir = camino_tempfile::tempdir().unwrap();
    for content in [&b""[..], &b"\n"[..]] {
        let file = write(&dir, "s", content);
        let e = read_secret_file(&file, FLAG).expect_err("an empty secret must be refused");
        assert!(format!("{e:#}").contains(FLAG), "{content:?}: {e:#}");
        assert!(
            format!("{e:#}").contains(file.as_str()),
            "{content:?}: {e:#}"
        );
    }
}

#[test]
fn a_missing_file_or_a_directory_fails_closed() {
    let dir = camino_tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    let e = read_secret_file(&missing, FLAG).unwrap_err();
    assert!(format!("{e:#}").contains(FLAG), "missing: {e:#}");
    assert!(
        format!("{e:#}").contains(missing.as_str()),
        "missing: {e:#}"
    );
    let e = read_secret_file(dir.path(), FLAG).unwrap_err();
    assert!(format!("{e:#}").contains(FLAG), "a directory: {e:#}");
}

#[test]
fn a_control_character_is_refused() {
    let dir = camino_tempfile::tempdir().unwrap();
    for content in [
        format!("{NEEDLE}\n\n"),
        format!("{NEEDLE}\r\n"),
        format!("{NEEDLE}\r"),
        format!("{NEEDLE}\nsecond\n"),
        format!("{NEEDLE}\nsecond"),
        format!("{NEEDLE}\t\n"),
        format!("{NEEDLE}\0\n"),
        format!("{NEEDLE}\u{1b}[0m\n"),
        format!("{NEEDLE}\u{7f}\n"),
        format!("{NEEDLE}\u{85}\n"),
        format!("\u{9b}{NEEDLE}\n"),
        format!("\n{NEEDLE}"),
    ] {
        let file = write(&dir, "s", content.as_bytes());
        let Err(e) = read_secret_file(&file, FLAG) else {
            panic!("{content:?} must be refused");
        };
        assert!(format!("{e:#}").contains(FLAG), "{content:?}: {e:#}");
        assert_clean(&e, &[NEEDLE]);
    }
    // A space and non-ASCII letters are no control characters.
    for content in ["p w\n", "pa\u{e9}ss\n"] {
        let file = write(&dir, "s", content.as_bytes());
        read_secret_file(&file, FLAG).unwrap();
    }
}

#[test]
fn an_oversized_or_non_utf8_file_is_refused() {
    let dir = camino_tempfile::tempdir().unwrap();
    let mut oversized = NEEDLE.as_bytes().to_vec();
    oversized.resize(64 * 1024 + 1, b'a');
    let mut not_utf8 = NEEDLE.as_bytes().to_vec();
    not_utf8.extend_from_slice(b"\xff\n");
    for (why, content) in [("oversized", oversized), ("not UTF-8", not_utf8)] {
        let file = write(&dir, "s", &content);
        let e = read_secret_file(&file, FLAG).expect_err(why);
        assert!(format!("{e:#}").contains(FLAG), "{why}: {e:#}");
        assert_clean(&e, &[NEEDLE]);
    }
    // Exactly the limit is still read.
    let file = write(&dir, "s", &vec![b'a'; 64 * 1024]);
    assert_eq!(read_secret_file(&file, FLAG).unwrap().len(), 64 * 1024);
}

#[test]
fn a_fifo_fails_at_once() {
    let dir = camino_tempfile::tempdir().unwrap();
    let fifo = dir.path().join("s.fifo");
    mkfifo(&fifo);
    let path = fifo.clone();
    let e = within_10s(&fifo, move || read_secret_file(&path, FLAG)).unwrap_err();
    assert!(format!("{e:#}").contains(FLAG), "{e:#}");
    assert!(format!("{e:#}").contains("regular file"), "{e:#}");
}

#[test]
fn a_symlink_to_a_regular_file_is_read() {
    let dir = camino_tempfile::tempdir().unwrap();
    let target = write(&dir, "real", format!("{NEEDLE}\n").as_bytes());
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(read_secret_file(&link, FLAG).unwrap(), NEEDLE);
}

#[test]
fn an_unreadable_file_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = camino_tempfile::tempdir().unwrap();
    let file = write(&dir, "s", format!("{NEEDLE}\n").as_bytes());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root reads a 0000 file anyway: nothing to check then.
    if std::fs::read(&file).is_ok() {
        return;
    }
    let e = read_secret_file(&file, FLAG).unwrap_err();
    assert!(format!("{e:#}").contains(FLAG), "{e:#}");
    assert_clean(&e, &[NEEDLE]);
}
