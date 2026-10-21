//! Final fix round (F1, item 3): `proxy --control-plane-token-file`, so the
//! control-plane JWT needn't be in `NEON_PROXY_TO_CONTROLPLANE_TOKEN` or on the
//! command line.
//!
//! Pinned (new):
//! - `ProxyCliArgs.control_plane_token_file: Option<Utf8PathBuf>`
//!   (`--control-plane-token-file`, no default): read once, at startup.
//! - `fn control_plane_token(args: &ProxyCliArgs) -> anyhow::Result<Arc<str>>`:
//!   with the file, its content with one trailing `\n` trimmed; an empty, missing
//!   or unreadable file, one that isn't a regular file, a control character in
//!   the token (`char::is_control`), or the file together with a non-empty
//!   `--control-plane-token` is an error naming `control-plane-token-file` and
//!   never the token. Without the file: `--control-plane-token` (or its env) as
//!   before. `build_auth_backend` takes the token from it (control-plane and
//!   console-redirect backends), so a bad file fails the startup.

use camino::Utf8Path;
use clap::Parser;

use super::{ProxyCliArgs, build_auth_backend, control_plane_token};

const CP_FLAG: &str = "control-plane-token-file";
const CP_TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.eyJmMSI6ImNwIn0.CpTokenNeedle";

fn assert_clean(e: &anyhow::Error, secrets: &[&str]) {
    for t in [format!("{e}"), format!("{e:#}"), format!("{e:?}")] {
        for s in secrets {
            assert!(!t.contains(s), "error text leaks {s:?}: {t}");
        }
    }
}

fn cp_args(file: Option<&Utf8Path>, extra: &[&str]) -> ProxyCliArgs {
    let mut argv: Vec<String> = vec!["proxy".into()];
    if let Some(file) = file {
        argv.push(format!("--{CP_FLAG}={file}"));
    }
    argv.extend(extra.iter().map(|s| s.to_string()));
    ProxyCliArgs::parse_from(argv)
}

#[test]
fn the_control_plane_token_file_flag_parses_without_a_default() {
    assert!(cp_args(None, &[]).control_plane_token_file.is_none());
    let args = cp_args(Some(Utf8Path::new("/run/proxy-api.token")), &[]);
    assert_eq!(
        args.control_plane_token_file.as_deref().map(|p| p.as_str()),
        Some("/run/proxy-api.token")
    );
}

#[test]
fn the_control_plane_token_comes_from_the_file() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy-api.token");
    for content in [format!("{CP_TOKEN}\n"), CP_TOKEN.to_string()] {
        std::fs::write(&file, &content).unwrap();
        let token = control_plane_token(&cp_args(Some(&file), &[])).unwrap();
        assert_eq!(&*token, CP_TOKEN, "{content:?}");
    }
    // Without the file, the flag's value as before (empty by default).
    let token = control_plane_token(&cp_args(None, &["--control-plane-token=fromflag"])).unwrap();
    assert_eq!(&*token, "fromflag");
    assert_eq!(&*control_plane_token(&cp_args(None, &[])).unwrap(), "");
}

#[test]
fn a_bad_control_plane_token_file_fails_closed() {
    let dir = camino_tempfile::tempdir().unwrap();
    let file = dir.path().join("proxy-api.token");
    let needle = "CpTokenNeedle";
    for (why, content) in [
        ("empty", "".to_string()),
        ("a newline only", "\n".to_string()),
        ("two trailing newlines", format!("{CP_TOKEN}\n\n")),
        ("CRLF", format!("{CP_TOKEN}\r\n")),
        ("two lines", format!("{CP_TOKEN}\nsecond")),
        ("NUL", format!("{CP_TOKEN}\0")),
        ("tab", format!("{CP_TOKEN}\t")),
        ("DEL", format!("{CP_TOKEN}\u{7f}")),
        ("C1 control", format!("{CP_TOKEN}\u{85}")),
    ] {
        std::fs::write(&file, &content).unwrap();
        let e = control_plane_token(&cp_args(Some(&file), &[]))
            .expect_err(&format!("{why}: must be refused"));
        assert!(format!("{e:#}").contains(CP_FLAG), "{why}: {e:#}");
        assert_clean(&e, &[needle]);
    }

    let missing = dir.path().join("missing.token");
    let e = control_plane_token(&cp_args(Some(&missing), &[])).unwrap_err();
    assert!(format!("{e:#}").contains(CP_FLAG), "missing: {e:#}");
    let e = control_plane_token(&cp_args(Some(dir.path()), &[])).unwrap_err();
    assert!(format!("{e:#}").contains(CP_FLAG), "a directory: {e:#}");

    // The file and a token on the command line (or in the environment) at once.
    std::fs::write(&file, format!("{CP_TOKEN}\n")).unwrap();
    let e = control_plane_token(&cp_args(
        Some(&file),
        &["--control-plane-token=OtherNeedle"],
    ))
    .unwrap_err();
    assert!(format!("{e:#}").contains(CP_FLAG), "both: {e:#}");
    assert_clean(&e, &[needle, "OtherNeedle"]);
}

#[tokio::test]
async fn the_control_plane_backends_refuse_to_start_without_their_token_file() {
    let dir = camino_tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.token");
    for backend in ["control-plane", "console-redirect"] {
        let args = cp_args(Some(&missing), &["--auth-backend", backend]);
        let Err(e) = build_auth_backend(&args) else {
            panic!("{backend}: a missing --{CP_FLAG} must fail the startup");
        };
        assert!(format!("{e:#}").contains(CP_FLAG), "{backend}: {e:#}");
    }
    let file = dir.path().join("proxy-api.token");
    std::fs::write(&file, format!("{CP_TOKEN}\n")).unwrap();
    for backend in ["control-plane", "console-redirect"] {
        let args = cp_args(Some(&file), &["--auth-backend", backend]);
        assert!(
            build_auth_backend(&args).is_ok(),
            "{backend} with a good file"
        );
    }
}
