//! Edge cases of `remote_storage::s3_timeout_config` beyond `s3_timeout.rs`.

use std::time::Duration;

use aws_smithy_types::timeout::TimeoutConfig;

#[test]
fn the_connect_timeout_is_ten_seconds() {
    assert_eq!(remote_storage::S3_CONNECT_TIMEOUT, Duration::from_secs(10));
}

#[test]
fn a_disabled_base_gets_a_connect_timeout_and_keeps_the_rest_disabled() {
    let mut tc = remote_storage::s3_timeout_config(Some(&TimeoutConfig::disabled()));
    assert_eq!(tc.connect_timeout(), Some(Duration::from_secs(10)));
    assert_eq!(tc.read_timeout(), None);
    assert_eq!(tc.operation_timeout(), None);
    assert_eq!(tc.operation_attempt_timeout(), None);
    // Disabled stays disabled (not merely unset, which SDK defaults could fill in).
    tc.take_defaults_from(
        &TimeoutConfig::builder()
            .read_timeout(Duration::from_secs(1))
            .build(),
    );
    assert_eq!(tc.read_timeout(), None);
}

#[test]
fn a_base_with_only_an_operation_timeout_keeps_it() {
    let base = TimeoutConfig::builder()
        .operation_timeout(Duration::from_secs(42))
        .build();
    let tc = remote_storage::s3_timeout_config(Some(&base));
    assert_eq!(tc.connect_timeout(), Some(Duration::from_secs(10)));
    assert_eq!(tc.operation_timeout(), Some(Duration::from_secs(42)));
    assert_eq!(tc.read_timeout(), None);
}

#[test]
fn a_longer_base_connect_timeout_is_kept() {
    let base = TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(60))
        .build();
    let tc = remote_storage::s3_timeout_config(Some(&base));
    assert_eq!(tc.connect_timeout(), Some(Duration::from_secs(60)));
}
