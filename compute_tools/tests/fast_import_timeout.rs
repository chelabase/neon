//! `fast_import` loads its AWS config with the SDK defaults of behavior version 2026-01-12, whose
//! 3.1 s connect timeout is too short for S3-compatible stores on slow links (ruling R-T0b-b).
//! It must set the 10 s connect timeout through `remote_storage::s3_timeout_config` (tested in
//! `libs/remote_storage/tests/s3_timeout.rs`). The binary's `main` can't run from a test, so this
//! pins the call site: the config loader chain passes the shared timeout config.

const SRC: &str = include_str!("../src/bin/fast_import.rs");

#[test]
fn aws_config_uses_the_shared_s3_timeout_config() {
    let defaults_at = SRC
        .find("aws_config::defaults(")
        .expect("fast_import loads its AWS config through aws_config::defaults");
    let rest = &SRC[defaults_at..];
    let load_at = rest
        .find(".load()")
        .expect("the loader chain ends in .load()");
    let chain = &rest[..load_at];
    assert!(
        chain.contains(".timeout_config(") && chain.contains("s3_timeout_config("),
        "the aws_config::defaults(..) chain must call .timeout_config(remote_storage::s3_timeout_config(..)), got:\n{chain}"
    );
}
