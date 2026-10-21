//! K8: `local_proxy --compute-ctl-token-file <path>`.
//!
//! Pinned (new): `LocalProxyCliArgs.compute_ctl_token_file: Utf8PathBuf`,
//! default `/var/db/postgres/compute_ctl_internal.token`; `build_auth_backend`
//! hands it to `LocalBackend::new` as `Some(path)`, whether or not the file
//! exists (SP19: no startup error).

use clap::Parser;

use super::{LocalProxyCliArgs, build_auth_backend};
use crate::auth::Backend;

fn parse(extra: &[&str]) -> LocalProxyCliArgs {
    let mut argv = vec!["local_proxy", "--http", "127.0.0.1:0"];
    argv.extend_from_slice(extra);
    LocalProxyCliArgs::parse_from(argv)
}

#[test]
fn the_default_path_is_the_chelabase_one() {
    let args = parse(&[]);
    assert_eq!(
        args.compute_ctl_token_file.as_str(),
        "/var/db/postgres/compute_ctl_internal.token"
    );
}

#[test]
fn the_flag_sets_the_path() {
    let args = parse(&["--compute-ctl-token-file", "/run/ctl.token"]);
    assert_eq!(args.compute_ctl_token_file.as_str(), "/run/ctl.token");
    let args = parse(&["--compute-ctl-token-file=/run/other.token"]);
    assert_eq!(args.compute_ctl_token_file.as_str(), "/run/other.token");
}

#[test]
fn the_backend_gets_the_path_even_when_the_file_is_missing() {
    let dir = camino_tempfile::tempdir().unwrap();
    let missing = dir.path().join("not-there.token");
    assert!(!missing.exists());
    let args = parse(&["--compute-ctl-token-file", missing.as_str()]);

    // Building the backend must not touch (or require) the file.
    let backend = build_auth_backend(&args);
    let Backend::Local(local) = backend else {
        panic!("local_proxy must build the Local backend");
    };
    assert_eq!(local.compute_ctl.token_file(), Some(missing.as_path()));
}

#[test]
fn the_default_path_reaches_the_backend() {
    let args = parse(&[]);
    let backend = build_auth_backend(&args);
    let Backend::Local(local) = backend else {
        panic!("local_proxy must build the Local backend");
    };
    assert_eq!(
        local.compute_ctl.token_file().map(|p| p.as_str()),
        Some("/var/db/postgres/compute_ctl_internal.token")
    );
}
