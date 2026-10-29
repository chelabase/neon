//! The compute spec's `compute_ctl_config.jwks` (a `jsonwebtoken` `JwkSet`) parses and
//! re-serialises unchanged across the `jsonwebtoken` 9 -> 11 move.
//!
//! `compute_ctl_config_v9.json` was serialised by jsonwebtoken 9.2.0 from a
//! `ComputeCtlConfig` holding the key shapes the compute sees: the Chelabase worker's
//! Ed25519 JWK (`kty`, `crv`, `x`, `kid`, `alg`, `use`), the shape `neon_local` builds
//! (plus `key_ops`), a bare Ed25519 JWK, an RS256 key (the Hadron path) and a P-256 key.

use compute_api::responses::ComputeCtlConfig;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm};
use serde_json::Value;

const V9: &str = include_str!("compute_ctl_config_v9.json");

/// `value` with every object's keys in sorted order (`serde_json::Value`'s map is a
/// `BTreeMap` here, but don't rely on the feature set).
fn canonical(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, canonical(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
        other => other,
    }
}

#[test]
fn v9_compute_ctl_config_round_trips() {
    let v9 = V9.trim_end();
    let config: ComputeCtlConfig = serde_json::from_str(v9).unwrap();
    let again = serde_json::to_string(&config).unwrap();
    assert_eq!(
        canonical(serde_json::from_str(&again).unwrap()),
        canonical(serde_json::from_str(v9).unwrap()),
    );
    // Not only the same JSON: the same bytes, field order included.
    assert_eq!(again, v9);
}

#[test]
fn v9_jwkset_round_trips_and_keeps_its_key_types() {
    let v9: Value = serde_json::from_str(V9).unwrap();
    let jwks: JwkSet = serde_json::from_value(v9["jwks"].clone()).unwrap();
    assert_eq!(
        canonical(serde_json::to_value(&jwks).unwrap()),
        canonical(v9["jwks"].clone())
    );

    let kinds: Vec<_> = jwks
        .keys
        .iter()
        .map(|jwk| {
            let kind = match &jwk.algorithm {
                AlgorithmParameters::OctetKeyPair(_) => "OKP",
                AlgorithmParameters::RSA(_) => "RSA",
                AlgorithmParameters::EllipticCurve(_) => "EC",
                _ => "other",
            };
            (kind, jwk.common.key_algorithm, jwk.common.key_id.as_deref())
        })
        .collect();
    assert_eq!(
        kinds,
        [
            ("OKP", Some(KeyAlgorithm::EdDSA), Some("5b2a3f0c9d1e7a44")),
            (
                "OKP",
                Some(KeyAlgorithm::EdDSA),
                Some("control-plane-shape")
            ),
            ("OKP", None, None),
            ("RSA", Some(KeyAlgorithm::RS256), Some("rsa-a")),
            ("EC", Some(KeyAlgorithm::ES256), Some("ec")),
        ]
    );
}

/// An empty set (`ComputeCtlConfig::default()`) serialises as `{"keys":[]}`.
#[test]
fn default_config_serialises_as_before() {
    assert_eq!(
        serde_json::to_string(&ComputeCtlConfig::default()).unwrap(),
        r#"{"jwks":{"keys":[]},"tls":null}"#
    );
}
