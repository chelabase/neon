//! Fork round 4, K3: the compute API types the token files and the storage
//! token refresh add (spec §8, RT4-2, RT4-3, RT4-8).
//!
//! Pinned interfaces (the code under test):
//! - `compute_api::spec::StorageAuthToken(String)`: `#[serde(transparent)]`, a
//!   hand-written `Debug` printing `StorageAuthToken(<redacted>)`, `pub fn
//!   as_str(&self) -> &str`; no `Display`, no `Deref`.
//! - `ComputeSpec.storage_auth_token: Option<StorageAuthToken>` (same JSON as
//!   before: a string or absent).
//! - `compute_api::requests::StorageTokenRequest { token: StorageAuthToken }`,
//!   the body of `POST /storage_token` (`{"token": "<jwt>"}`).
//! - `compute_api::responses::ComputeStatusResponse.capabilities: Vec<String>`,
//!   `#[serde(default)]` (an older compute_ctl's `/status` has none).

use compute_api::requests::{ConfigurationRequest, StorageTokenRequest};
use compute_api::responses::{ComputeStatusResponse, PromoteConfig};
use compute_api::spec::{ComputeSpec, StorageAuthToken};
use serde_json::{Value, json};

const SPEC: &str = include_str!("cluster_spec.json");

/// Distinctive, valid token text: any of it showing up in a `Debug` is a leak.
const TOKEN: &str = "k3secret.eyJzdWIiOiJ0ZW5hbnQifQ.zz9-_~+/=";
const NEEDLE: &str = "k3secret";

fn spec_json(token: Option<&str>) -> Value {
    let mut json: Value = serde_json::from_str(SPEC).unwrap();
    match token {
        Some(token) => json["storage_auth_token"] = json!(token),
        None => {
            json.as_object_mut().unwrap().remove("storage_auth_token");
        }
    }
    json
}

fn spec(token: Option<&str>) -> ComputeSpec {
    serde_json::from_value(spec_json(token)).unwrap()
}

#[test]
fn the_storage_token_keeps_its_json_form() {
    let with = spec(Some(TOKEN));
    let token: &StorageAuthToken = with.storage_auth_token.as_ref().expect("token parsed");
    assert_eq!(token.as_str(), TOKEN);
    // Transparent: serialised back as the plain string.
    let back = serde_json::to_value(&with).unwrap();
    assert_eq!(back["storage_auth_token"], json!(TOKEN));
    let alone: StorageAuthToken = serde_json::from_value(json!(TOKEN)).unwrap();
    assert_eq!(serde_json::to_value(&alone).unwrap(), json!(TOKEN));

    assert!(spec(None).storage_auth_token.is_none());
    let mut null = spec_json(None);
    null["storage_auth_token"] = Value::Null;
    let null: ComputeSpec = serde_json::from_value(null).unwrap();
    assert!(null.storage_auth_token.is_none());
}

#[test]
fn no_debug_of_a_spec_prints_the_token() {
    let token: StorageAuthToken = serde_json::from_value(json!(TOKEN)).unwrap();
    for text in [format!("{token:?}"), format!("{token:#?}")] {
        assert_eq!(text, "StorageAuthToken(<redacted>)");
    }

    let spec = spec(Some(TOKEN));
    for text in [format!("{spec:?}"), format!("{spec:#?}")] {
        assert!(!text.contains(NEEDLE), "ComputeSpec Debug leaks the token");
        assert!(text.contains("StorageAuthToken(<redacted>)"), "{text}");
    }

    // The request types that carry a spec (the /configure and /promote bodies,
    // logged by `spec_apply.rs` and `compute_promote.rs`).
    let configure: ConfigurationRequest = serde_json::from_value(json!({
        "spec": spec_json(Some(TOKEN)),
        "compute_ctl_config": {"jwks": {"keys": []}, "tls": null},
    }))
    .unwrap();
    let promote: PromoteConfig = serde_json::from_value(json!({
        "spec": spec_json(Some(TOKEN)),
        "wal_flush_lsn": "0/16B9188",
    }))
    .unwrap();
    for text in [
        format!("{configure:?}"),
        format!("{configure:#?}"),
        format!("{promote:?}"),
        format!("{promote:#?}"),
    ] {
        assert!(
            !text.contains(NEEDLE),
            "a spec-carrying request leaks the token"
        );
    }
}

#[test]
fn the_refresh_body_is_one_token() {
    let body: StorageTokenRequest = serde_json::from_value(json!({ "token": TOKEN })).unwrap();
    assert_eq!(body.token.as_str(), TOKEN);
    assert!(
        !format!("{body:?}").contains(NEEDLE),
        "StorageTokenRequest Debug leaks"
    );
    assert!(serde_json::from_value::<StorageTokenRequest>(json!({})).is_err());
    assert!(serde_json::from_value::<StorageTokenRequest>(json!({ "token": 5 })).is_err());
}

#[test]
fn status_capabilities_default_to_none() {
    let old = json!({
        "start_time": "2026-10-21T00:00:00Z",
        "tenant": null,
        "timeline": null,
        "status": "running",
        "last_active": null,
        "error": null,
    });
    let parsed: ComputeStatusResponse = serde_json::from_value(old.clone()).unwrap();
    assert!(
        parsed.capabilities.is_empty(),
        "an older compute_ctl advertises nothing"
    );

    let mut new = old;
    new["capabilities"] = json!(["storage_token_refresh"]);
    let parsed: ComputeStatusResponse = serde_json::from_value(new).unwrap();
    assert_eq!(
        parsed.capabilities,
        vec!["storage_token_refresh".to_string()]
    );
    let back = serde_json::to_value(&parsed).unwrap();
    assert_eq!(back["capabilities"], json!(["storage_token_refresh"]));
}
