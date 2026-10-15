//! Behavior version 2026-01-12 defaults the connect timeout to 3.1 s, too short for S3-compatible
//! stores on slow links. The S3 client sets it to 10 s explicitly (ruling R-T0b-b), without
//! dropping the other timeouts the SDK config carries (operation, operation-attempt, read).

use std::num::NonZeroUsize;
use std::time::Duration;

use aws_smithy_types::timeout::TimeoutConfig;
use remote_storage::{S3Bucket, S3Config};

#[test]
fn timeout_config_defaults_connect_to_ten_seconds() {
    let tc = remote_storage::s3_timeout_config(None);
    assert_eq!(tc.connect_timeout(), Some(Duration::from_secs(10)));
    assert_eq!(tc.read_timeout(), None);
    assert_eq!(tc.operation_timeout(), None);
    assert_eq!(tc.operation_attempt_timeout(), None);
}

#[test]
fn timeout_config_keeps_the_other_timeouts_of_the_base() {
    let base = TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(1))
        .read_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(7))
        .operation_attempt_timeout(Duration::from_secs(3))
        .build();
    let tc = remote_storage::s3_timeout_config(Some(&base));
    assert_eq!(tc.connect_timeout(), Some(Duration::from_secs(10)));
    assert_eq!(tc.read_timeout(), Some(Duration::from_secs(5)));
    assert_eq!(tc.operation_timeout(), Some(Duration::from_secs(7)));
    assert_eq!(tc.operation_attempt_timeout(), Some(Duration::from_secs(3)));
}

#[tokio::test]
async fn built_client_has_a_ten_second_connect_timeout() {
    for endpoint in [None, Some("http://127.0.0.1:9".to_string())] {
        let config = S3Config {
            bucket_name: "bucket".to_owned(),
            bucket_region: "region".to_owned(),
            prefix_in_bucket: None,
            endpoint,
            concurrency_limit: NonZeroUsize::new(100).unwrap(),
            max_keys_per_list_response: Some(5),
            upload_storage_class: None,
        };
        let storage = S3Bucket::new(&config, Duration::from_secs(30))
            .await
            .expect("bucket construction does not touch the network");
        let tc = storage
            .client_timeout_config()
            .expect("the S3 client carries a timeout config");
        assert_eq!(tc.connect_timeout(), Some(Duration::from_secs(10)));
    }
}
