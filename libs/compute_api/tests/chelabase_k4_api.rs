//! Fork round 4, K4: the compute API types of the metrics scope (spec §7, U4)
//! and the realtime logins (spec §10, W31).
//!
//! Pinned interfaces (the code under test):
//! - `compute_api::requests::ComputeClaimsScope::Metrics`: serde `"metrics"`,
//!   and `FromStr` `"metrics"` (neon_local's `--scope metrics`); `Admin` keeps
//!   `"compute_ctl:admin"`.
//! - `compute_api::spec::ComputeSpec.realtime_logins: Option<MemberLogins>`,
//!   `#[serde(default)]`, JSON key `"realtime_logins"`, the same shape as
//!   `member_logins` (`allowed_cidrs`, `client_cns`).

use std::str::FromStr;

use compute_api::requests::{ComputeClaims, ComputeClaimsScope};
use compute_api::spec::{ComputeSpec, MemberLogins};
use serde_json::{Value, json};

const SPEC: &str = include_str!("cluster_spec.json");

#[test]
fn the_metrics_scope_is_metrics_both_ways() {
    let from_serde: ComputeClaimsScope = serde_json::from_str("\"metrics\"").unwrap();
    assert_eq!(from_serde, ComputeClaimsScope::Metrics);
    assert_eq!(
        ComputeClaimsScope::from_str("metrics").unwrap(),
        ComputeClaimsScope::Metrics
    );
    assert_eq!(
        serde_json::to_value(ComputeClaimsScope::Metrics).unwrap(),
        json!("metrics")
    );
    // The admin scope is unchanged, and nothing else parses.
    assert_eq!(
        ComputeClaimsScope::from_str("compute_ctl:admin").unwrap(),
        ComputeClaimsScope::Admin
    );
    for bad in ["Metrics", "METRICS", "metrics ", "compute_ctl:metrics", ""] {
        assert!(ComputeClaimsScope::from_str(bad).is_err(), "{bad:?}");
        assert!(
            serde_json::from_value::<ComputeClaimsScope>(json!(bad)).is_err(),
            "{bad:?}"
        );
    }
}

/// Chelabase's metrics token (`{"scope":"metrics","iat":…}`, no `compute_id`,
/// no `aud`, no `exp`) and neon_local's (`compute_id` set) decode as claims.
#[test]
fn metrics_claims_decode() {
    let claims: ComputeClaims =
        serde_json::from_value(json!({ "scope": "metrics", "iat": 1_700_000_000 })).unwrap();
    assert_eq!(claims.scope, Some(ComputeClaimsScope::Metrics));
    assert!(claims.compute_id.is_none());
    assert!(claims.audience.is_none());

    let claims: ComputeClaims =
        serde_json::from_value(json!({ "scope": "metrics", "compute_id": "ep-1" })).unwrap();
    assert_eq!(claims.scope, Some(ComputeClaimsScope::Metrics));
    assert_eq!(claims.compute_id.as_deref(), Some("ep-1"));
}

fn spec_json() -> Value {
    serde_json::from_str(SPEC).unwrap()
}

#[test]
fn realtime_logins_default_to_none() {
    let json = spec_json();
    assert!(
        json.get("realtime_logins").is_none(),
        "the sample spec has no realtime_logins"
    );
    let spec: ComputeSpec = serde_json::from_value(json).unwrap();
    assert!(spec.realtime_logins.is_none());

    let mut null = spec_json();
    null["realtime_logins"] = Value::Null;
    let spec: ComputeSpec = serde_json::from_value(null).unwrap();
    assert!(spec.realtime_logins.is_none());
}

#[test]
fn realtime_logins_keep_their_json_form() {
    let mut json = spec_json();
    json["realtime_logins"] = json!({
        "allowed_cidrs": ["10.213.4.12/32", "10.213.4.11/32"],
        "client_cns": ["chelabase-realtime"],
    });
    json["member_logins"] = json!({
        "allowed_cidrs": ["10.213.4.10/32"],
        "client_cns": ["chelabase-orchestrator"],
    });
    let spec: ComputeSpec = serde_json::from_value(json).unwrap();
    let realtime: &MemberLogins = spec.realtime_logins.as_ref().expect("parsed");
    assert_eq!(
        realtime.allowed_cidrs,
        vec!["10.213.4.12/32".to_string(), "10.213.4.11/32".to_string()]
    );
    assert_eq!(realtime.client_cns, vec!["chelabase-realtime".to_string()]);
    let member = spec.member_logins.as_ref().expect("parsed");
    assert_eq!(
        member.client_cns,
        vec!["chelabase-orchestrator".to_string()]
    );

    let back = serde_json::to_value(&spec).unwrap();
    assert_eq!(
        back["realtime_logins"],
        json!({
            "allowed_cidrs": ["10.213.4.12/32", "10.213.4.11/32"],
            "client_cns": ["chelabase-realtime"],
        })
    );

    // An empty list is kept (no address rule), never confused with an absent block.
    let mut empty = spec_json();
    empty["realtime_logins"] = json!({ "allowed_cidrs": [], "client_cns": ["chelabase-realtime"] });
    let spec: ComputeSpec = serde_json::from_value(empty).unwrap();
    assert!(
        spec.realtime_logins
            .as_ref()
            .is_some_and(|r| r.allowed_cidrs.is_empty())
    );
}
