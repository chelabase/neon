//! F6: the pageserver reads the token it presents to the safekeepers from a file
//! (`--auth-token-file`), so it needn't be in `NEON_AUTH_TOKEN` in its environment.
//!
//! Pinned:
//! - `cli()` takes `--auth-token-file <path>` (arg id `auth-token-file`, a `String` like
//!   `workdir`, no default).
//! - `fn safekeeper_auth_token(token_file: Option<&Utf8Path>, env: Result<String, VarError>)
//!   -> anyhow::Result<Option<String>>`: `main` passes the flag's path and
//!   `std::env::var("NEON_AUTH_TOKEN")`, and sets `SAFEKEEPER_AUTH_TOKEN` from a `Some`.
//!   With the file: its content read by `utils::secret_file::read_secret_file` (one trailing
//!   `\n` trimmed); a missing, empty, non-regular file or a control character in it is an
//!   error naming `--auth-token-file`, never the token. The file together with a present
//!   `NEON_AUTH_TOKEN` is an error naming `--auth-token-file`. Without the file: the variable
//!   as before (`NotPresent` is `None`, `NotUnicode` an error).

use std::env::VarError;
use std::ffi::OsString;
use std::time::Duration;

use super::{cli, safekeeper_auth_token};

const FLAG: &str = "--auth-token-file";
const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.eyJzY29wZSI6InNhZmVrZWVwZXJkYXRhIn0.PsTokenNeedle";
const NEEDLE: &str = "PsTokenNeedle";

fn err_text(e: &anyhow::Error) -> String {
    format!("{e} | {e:#} | {e:?}")
}

#[test]
fn the_flag_parses_without_a_default() {
    let m = cli().try_get_matches_from(["pageserver"]).unwrap();
    assert!(m.get_one::<String>("auth-token-file").is_none());
    let m = cli()
        .try_get_matches_from([
            "pageserver",
            "-D",
            "/data/.neon",
            "--auth-token-file=/run/safekeeper-data.jwt",
        ])
        .unwrap();
    assert_eq!(
        m.get_one::<String>("auth-token-file").map(String::as_str),
        Some("/run/safekeeper-data.jwt")
    );
    assert_eq!(
        m.get_one::<String>("workdir").map(String::as_str),
        Some("/data/.neon")
    );
}

#[test]
fn the_token_comes_from_the_file() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("safekeeper-data.jwt");
    for content in [format!("{TOKEN}\n"), TOKEN.to_string()] {
        std::fs::write(&file, &content).unwrap();
        let token = safekeeper_auth_token(Some(file.as_path()), Err(VarError::NotPresent)).unwrap();
        assert_eq!(token.as_deref(), Some(TOKEN), "{content:?}");
    }
}

#[test]
fn without_the_file_the_variable_works_as_before() {
    assert_eq!(
        safekeeper_auth_token(None, Ok("fromenv".to_string())).unwrap(),
        Some("fromenv".to_string())
    );
    assert_eq!(
        safekeeper_auth_token(None, Err(VarError::NotPresent)).unwrap(),
        None
    );
    let e = safekeeper_auth_token(None, Err(VarError::NotUnicode(OsString::from("x"))))
        .expect_err("a non-UTF-8 NEON_AUTH_TOKEN is an error, as before");
    assert!(err_text(&e).contains("NEON_AUTH_TOKEN"), "{}", err_text(&e));
}

#[test]
fn a_bad_token_file_fails_closed() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("safekeeper-data.jwt");
    for (why, content) in [
        ("empty", String::new()),
        ("a newline only", "\n".to_string()),
        ("two trailing newlines", format!("{TOKEN}\n\n")),
        ("CRLF", format!("{TOKEN}\r\n")),
        ("two lines", format!("{TOKEN}\nsecond")),
        ("NUL", format!("{TOKEN}\0")),
        ("tab", format!("{TOKEN}\t")),
        ("DEL", format!("{TOKEN}\u{7f}")),
        ("C1 control", format!("{TOKEN}\u{85}")),
    ] {
        std::fs::write(&file, &content).unwrap();
        let e = safekeeper_auth_token(Some(file.as_path()), Err(VarError::NotPresent))
            .expect_err(&format!("{why}: must be refused"));
        let text = err_text(&e);
        assert!(text.contains(FLAG), "{why}: {text}");
        assert!(!text.contains(NEEDLE), "{why} leaks the token: {text}");
    }

    let missing = dir.path().join("missing.jwt");
    let e = safekeeper_auth_token(Some(missing.as_path()), Err(VarError::NotPresent)).unwrap_err();
    assert!(err_text(&e).contains(FLAG), "missing: {}", err_text(&e));
    let e = safekeeper_auth_token(Some(dir.path()), Err(VarError::NotPresent)).unwrap_err();
    assert!(err_text(&e).contains(FLAG), "a directory: {}", err_text(&e));
}

#[test]
fn a_fifo_token_file_fails_at_once() {
    let dir = camino_tempfile::tempdir().unwrap();
    let fifo = dir.path().join("safekeeper-data.jwt");
    let made = std::process::Command::new("mkfifo")
        .arg(fifo.as_str())
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo failed");
    let path = fifo.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        drop(
            tx.send(
                safekeeper_auth_token(Some(path.as_path()), Err(VarError::NotPresent))
                    .map_err(|e| err_text(&e)),
            ),
        )
    });
    let r = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(r) => r,
        Err(_) => {
            std::thread::spawn(move || drop(std::fs::OpenOptions::new().write(true).open(fifo)));
            panic!("reading the token file blocked on a FIFO");
        }
    };
    let e = r.expect_err("a FIFO must be refused");
    assert!(e.contains(FLAG), "{e}");
    assert!(e.contains("regular file"), "{e}");
}

#[test]
fn the_file_and_the_variable_together_are_an_error() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("safekeeper-data.jwt");
    std::fs::write(&file, format!("{TOKEN}\n")).unwrap();
    for env in ["EnvTokenNeedle", ""] {
        let e = safekeeper_auth_token(Some(file.as_path()), Ok(env.to_string()))
            .expect_err("the file and NEON_AUTH_TOKEN at once must be refused");
        let text = err_text(&e);
        assert!(text.contains(FLAG), "{env:?}: {text}");
        assert!(!text.contains(NEEDLE), "leaks the file's token: {text}");
        assert!(
            !text.contains("EnvTokenNeedle"),
            "leaks the variable: {text}"
        );
    }
    // A non-UTF-8 variable beside the file is present too.
    let e = safekeeper_auth_token(
        Some(file.as_path()),
        Err(VarError::NotUnicode(OsString::from("x"))),
    )
    .expect_err("a non-UTF-8 NEON_AUTH_TOKEN beside the file must be refused");
    assert!(err_text(&e).contains(FLAG), "{}", err_text(&e));
}
