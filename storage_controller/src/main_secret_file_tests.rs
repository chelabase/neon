//! F6: the storage controller reads its outgoing tokens from files, so none of them has to be
//! in its process environment (or on its command line).
//!
//! Pinned:
//! - `Cli.pageserver_jwt_token_file`, `Cli.safekeeper_jwt_token_file`,
//!   `Cli.control_plane_jwt_token_file`: `Option<Utf8PathBuf>`, no default
//!   (`--pageserver-jwt-token-file`, `--safekeeper-jwt-token-file`,
//!   `--control-plane-jwt-token-file`).
//! - `Secrets::load_with_env(args: &Cli, env: &dyn Fn(&str) -> Option<String>)
//!   -> anyhow::Result<Secrets>`: what `Secrets::load` does, with the environment read through
//!   `env` (`load` passes `|name| std::env::var(name).ok()`). With a token file, the token is
//!   the file's content read by `utils::secret_file::read_secret_file` (one trailing `\n`
//!   trimmed); a missing, empty, non-regular file or a control character in it is an error
//!   naming the file flag and never the token. A file flag together with its counterpart
//!   (the flag `--jwt-token` / `--safekeeper-jwt-token` / `--control-plane-jwt-token`, or the
//!   variable `PAGESERVER_JWT_TOKEN` / `SAFEKEEPER_JWT_TOKEN` / `CONTROL_PLANE_JWT_TOKEN`) is
//!   a startup error naming the file flag (a clap conflict at parse time is fine for the
//!   flag counterpart). Without the file flag: the flag, else the variable, as before.

use std::time::Duration;

use camino::Utf8Path;
use clap::Parser;

use super::{Cli, Secrets};

const DB: &str = "--database-url=postgresql://storcon:storcon@127.0.0.1:1/storage_controller";
const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.eyJzY29wZSI6ImY2In0.StorconTokenNeedle";
const NEEDLE: &str = "StorconTokenNeedle";

/// One outgoing token: its file flag, its old flag, its variable and its `Secrets` field.
struct Token {
    file_flag: &'static str,
    flag: &'static str,
    env: &'static str,
    field: fn(&Secrets) -> Option<&str>,
}

const TOKENS: [Token; 3] = [
    Token {
        file_flag: "--pageserver-jwt-token-file",
        flag: "--jwt-token",
        env: "PAGESERVER_JWT_TOKEN",
        field: |s| s.pageserver_jwt_token.as_deref(),
    },
    Token {
        file_flag: "--safekeeper-jwt-token-file",
        flag: "--safekeeper-jwt-token",
        env: "SAFEKEEPER_JWT_TOKEN",
        field: |s| s.safekeeper_jwt_token.as_deref(),
    },
    Token {
        file_flag: "--control-plane-jwt-token-file",
        flag: "--control-plane-jwt-token",
        env: "CONTROL_PLANE_JWT_TOKEN",
        field: |s| s.control_plane_jwt_token.as_deref(),
    },
];

fn argv(extra: &[String]) -> Vec<String> {
    let mut argv = vec![
        "storage_controller".to_string(),
        "--listen=127.0.0.1:1234".to_string(),
        DB.to_string(),
    ];
    argv.extend(extra.iter().cloned());
    argv
}

/// Parses `extra` and loads the secrets with the variables in `env`; any error (clap's or
/// the load's) as its full text.
fn load(extra: &[String], env: &[(&str, &str)]) -> Result<Secrets, String> {
    let args = Cli::try_parse_from(argv(extra)).map_err(|e| e.to_string())?;
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let lookup = move |name: &str| env.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    Secrets::load_with_env(&args, &lookup).map_err(|e| format!("{e} | {e:#} | {e:?}"))
}

fn expect_err(r: Result<Secrets, String>, why: &str) -> String {
    match r {
        Ok(_) => panic!("{why}: expected a startup error"),
        Err(e) => e,
    }
}

fn file_arg(t: &Token, path: &Utf8Path) -> String {
    format!("{}={path}", t.file_flag)
}

#[test]
fn the_file_flags_parse_without_a_default() {
    let args = Cli::try_parse_from(argv(&[])).unwrap();
    assert!(args.pageserver_jwt_token_file.is_none());
    assert!(args.safekeeper_jwt_token_file.is_none());
    assert!(args.control_plane_jwt_token_file.is_none());
    let args = Cli::try_parse_from(argv(&[
        "--pageserver-jwt-token-file=/run/pageserver-api.jwt".into(),
        "--safekeeper-jwt-token-file=/run/safekeeper-data.jwt".into(),
        "--control-plane-jwt-token-file=/run/storcon-hook.token".into(),
    ]))
    .unwrap();
    assert_eq!(
        args.pageserver_jwt_token_file
            .as_deref()
            .map(|p| p.as_str()),
        Some("/run/pageserver-api.jwt")
    );
    assert_eq!(
        args.safekeeper_jwt_token_file
            .as_deref()
            .map(|p| p.as_str()),
        Some("/run/safekeeper-data.jwt")
    );
    assert_eq!(
        args.control_plane_jwt_token_file
            .as_deref()
            .map(|p| p.as_str()),
        Some("/run/storcon-hook.token")
    );
}

#[test]
fn each_token_comes_from_its_file() {
    let dir = camino_tempfile::tempdir().unwrap();
    for t in &TOKENS {
        for content in [format!("{TOKEN}\n"), TOKEN.to_string()] {
            let file = dir.path().join("t.jwt");
            std::fs::write(&file, &content).unwrap();
            let secrets =
                load(&[file_arg(t, &file)], &[]).unwrap_or_else(|e| panic!("{}: {e}", t.file_flag));
            assert_eq!(
                (t.field)(&secrets),
                Some(TOKEN),
                "{} {content:?}",
                t.file_flag
            );
            // The other tokens are untouched.
            for other in TOKENS.iter().filter(|o| o.file_flag != t.file_flag) {
                assert_eq!(
                    (other.field)(&secrets),
                    None,
                    "{} set {}",
                    t.file_flag,
                    other.file_flag
                );
            }
        }
    }
}

#[test]
fn all_three_files_together() {
    let dir = camino_tempfile::tempdir().unwrap();
    let mut extra = Vec::new();
    for (i, t) in TOKENS.iter().enumerate() {
        let file = dir.path().join(format!("t{i}.jwt"));
        std::fs::write(&file, format!("token-{i}\n")).unwrap();
        extra.push(file_arg(t, &file));
    }
    let secrets = load(&extra, &[]).unwrap_or_else(|e| panic!("{e}"));
    for (i, t) in TOKENS.iter().enumerate() {
        assert_eq!(
            (t.field)(&secrets),
            Some(format!("token-{i}").as_str()),
            "{}",
            t.file_flag
        );
    }
}

#[test]
fn without_a_file_the_flag_or_the_variable_works_as_before() {
    for t in &TOKENS {
        let secrets = load(&[format!("{}=fromflag", t.flag)], &[]).unwrap();
        assert_eq!((t.field)(&secrets), Some("fromflag"), "{}", t.flag);
        let secrets = load(&[], &[(t.env, "fromenv")]).unwrap();
        assert_eq!((t.field)(&secrets), Some("fromenv"), "{}", t.env);
        let secrets = load(&[], &[]).unwrap();
        assert_eq!((t.field)(&secrets), None, "{}", t.file_flag);
    }
}

#[test]
fn a_bad_token_file_fails_closed() {
    let dir = camino_tempfile::tempdir().unwrap();
    for t in &TOKENS {
        let file = dir.path().join("t.jwt");
        for (why, content) in [
            ("empty", String::new()),
            ("a newline only", "\n".to_string()),
            ("two trailing newlines", format!("{TOKEN}\n\n")),
            ("CRLF", format!("{TOKEN}\r\n")),
            ("two lines", format!("{TOKEN}\nsecond")),
            ("NUL", format!("{TOKEN}\0")),
            ("tab", format!("{TOKEN}\t")),
            ("ESC", format!("{TOKEN}\u{1b}[0m")),
            ("DEL", format!("{TOKEN}\u{7f}")),
            ("C1 control", format!("{TOKEN}\u{85}")),
        ] {
            std::fs::write(&file, &content).unwrap();
            let e = expect_err(load(&[file_arg(t, &file)], &[]), why);
            assert!(e.contains(t.file_flag), "{} {why}: {e}", t.file_flag);
            assert!(
                !e.contains(NEEDLE),
                "{} {why} leaks the token: {e}",
                t.file_flag
            );
        }

        let missing = dir.path().join("missing.jwt");
        let e = expect_err(load(&[file_arg(t, &missing)], &[]), "missing");
        assert!(e.contains(t.file_flag), "{} missing: {e}", t.file_flag);
        let e = expect_err(load(&[file_arg(t, dir.path())], &[]), "a directory");
        assert!(e.contains(t.file_flag), "{} a directory: {e}", t.file_flag);
    }
}

fn mkfifo(path: &Utf8Path) {
    let made = std::process::Command::new("mkfifo")
        .arg(path.as_str())
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo failed");
}

#[test]
fn a_fifo_token_file_fails_at_once() {
    let dir = camino_tempfile::tempdir().unwrap();
    for t in &TOKENS {
        let fifo = dir.path().join(format!("{}.fifo", t.env));
        mkfifo(&fifo);
        let extra = vec![file_arg(t, &fifo)];
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || drop(tx.send(load(&extra, &[]).map(|_| ()))));
        let r = match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(r) => r,
            Err(_) => {
                let fifo = fifo.clone();
                std::thread::spawn(move || {
                    drop(std::fs::OpenOptions::new().write(true).open(fifo))
                });
                panic!("{}: reading the token file blocked on a FIFO", t.file_flag);
            }
        };
        let e = r.expect_err("a FIFO must be refused");
        assert!(e.contains(t.file_flag), "{}: {e}", t.file_flag);
        assert!(e.contains("regular file"), "{}: {e}", t.file_flag);
    }
}

#[test]
fn the_file_and_its_counterpart_together_are_a_startup_error() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("t.jwt");
    std::fs::write(&file, format!("{TOKEN}\n")).unwrap();
    for t in &TOKENS {
        // The variable beside the file (set, even empty, is given).
        for env in ["EnvTokenNeedle", ""] {
            let e = expect_err(
                load(&[file_arg(t, &file)], &[(t.env, env)]),
                "file and variable",
            );
            assert!(
                e.contains(t.file_flag),
                "{} with {}={env:?}: {e}",
                t.file_flag,
                t.env
            );
            assert!(
                !e.contains(NEEDLE),
                "{}: leaks the file's token: {e}",
                t.file_flag
            );
            assert!(
                !e.contains("EnvTokenNeedle"),
                "{}: leaks the variable: {e}",
                t.file_flag
            );
        }

        // The flag beside the file (refused by clap or by the load).
        let e = expect_err(
            load(
                &[file_arg(t, &file), format!("{}=FlagTokenNeedle", t.flag)],
                &[],
            ),
            "file and flag",
        );
        assert!(
            e.contains(t.file_flag),
            "{} with {}: {e}",
            t.file_flag,
            t.flag
        );
        assert!(
            !e.contains(NEEDLE),
            "{}: leaks the file's token: {e}",
            t.file_flag
        );
        assert!(
            !e.contains("FlagTokenNeedle"),
            "{}: leaks the flag's token: {e}",
            t.file_flag
        );

        // Another token's variable is no conflict.
        for other in TOKENS.iter().filter(|o| o.env != t.env) {
            let secrets = load(&[file_arg(t, &file)], &[(other.env, "other")])
                .unwrap_or_else(|e| panic!("{} beside {}: {e}", t.file_flag, other.env));
            assert_eq!((t.field)(&secrets), Some(TOKEN));
            assert_eq!((other.field)(&secrets), Some("other"));
        }
    }
}
