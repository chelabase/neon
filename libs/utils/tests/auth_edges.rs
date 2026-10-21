//! Edge cases of storage token validation (`utils::auth::JwtAuth`): `exp` is optional,
//! but a token that carries one is held to it.

use jsonwebtoken::{DecodingKey, get_current_timestamp};
use utils::auth::{Claims, JwtAuth, Scope, encode_from_key_file};

// The test key pair of `utils::auth`'s unit tests.
const TEST_PUB_KEY_ED25519: &str = r#"
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARYwaNBayR+eGI0iXB4s3QxE3Nl2g1iWbr6KtLWeVD/w=
-----END PUBLIC KEY-----
"#;

const TEST_PRIV_KEY_ED25519: &str = r#"
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID/Drmc1AA6U/znNRWpF3zEGegOATQxfkdWxitcOMsIH
-----END PRIVATE KEY-----
"#;

fn auth() -> JwtAuth {
    JwtAuth::new(vec![
        DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap(),
    ])
}

fn sign(claims: serde_json::Value) -> String {
    encode_from_key_file(&claims, &pem::parse(TEST_PRIV_KEY_ED25519).unwrap()).unwrap()
}

#[test]
fn expired_exp_is_refused_and_future_or_absent_exp_accepted() {
    let auth = auth();
    let now = get_current_timestamp();

    let expired = auth
        .decode::<Claims>(&sign(
            serde_json::json!({"scope": "metrics", "exp": now - 120}),
        ))
        .expect_err("a token expired beyond the 60 s leeway is refused");
    assert!(expired.0.contains("ExpiredSignature"), "{expired}");

    let future = auth
        .decode::<Claims>(&sign(
            serde_json::json!({"scope": "metrics", "exp": now + 3600}),
        ))
        .expect("a token with a future exp decodes");
    assert_eq!(future.claims.scope, Scope::Metrics);

    auth.decode::<Claims>(&sign(serde_json::json!({"scope": "metrics", "iat": now})))
        .expect("a token without exp decodes");
}

/// The validation skips an `exp` or `nbf` it can't parse as an integer, so such a token
/// would never expire: it is refused instead.
#[test]
fn non_numeric_exp_or_nbf_is_refused() {
    let auth = auth();
    let now = get_current_timestamp();
    for (name, value) in [
        ("exp", serde_json::json!((now - 3600).to_string())),
        ("exp", serde_json::json!((now + 3600).to_string())),
        ("exp", serde_json::json!(now as f64 + 3600.5)),
        ("exp", serde_json::json!(-1)),
        ("exp", serde_json::Value::Null),
        ("nbf", serde_json::json!(now.to_string())),
    ] {
        let mut claims = serde_json::json!({"scope": "pageserverapi"});
        claims[name] = value.clone();
        let err = auth
            .decode::<Claims>(&sign(claims))
            .expect_err(&format!("`{name}`: {value} is refused"));
        assert!(err.0.contains("NumericDate"), "`{name}`: {value}: {err}");
    }
}

/// A token signed by another key is refused, and so is a payload that isn't `Claims`.
#[test]
fn bad_signature_and_bad_claims_are_refused() {
    let other = JwtAuth::new(vec![
        DecodingKey::from_ed_pem(
            b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAkRtA2tEBfAx8ErsdhrhJVJkQNtNo1nnfOuDWgqZ8MPs=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap(),
    ]);
    let token = sign(serde_json::json!({"scope": "metrics"}));
    let err = other
        .decode::<Claims>(&token)
        .expect_err("another key's token");
    assert!(err.0.contains("InvalidSignature"), "{err}");

    let err = auth()
        .decode::<Claims>(&sign(serde_json::json!({"scope": "superuser"})))
        .expect_err("an unknown scope");
    assert!(err.0.contains("unknown variant"), "{err}");
}

/// With several keys, a token verifies against whichever key signed it.
#[test]
fn second_key_verifies() {
    let auth = JwtAuth::new(vec![
        DecodingKey::from_ed_pem(
            b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAkRtA2tEBfAx8ErsdhrhJVJkQNtNo1nnfOuDWgqZ8MPs=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap(),
        DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap(),
    ]);
    let data = auth
        .decode::<Claims>(&sign(serde_json::json!({"scope": "metrics"})))
        .expect("the second key verifies");
    assert_eq!(data.claims.scope, Scope::Metrics);
    assert_eq!(data.claims.tenant_id, None);
}
