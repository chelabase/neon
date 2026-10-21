//! `nbf` (not before) on storage tokens (K7 fix round): a token that carries one isn't
//! valid before that time, with the same 60 s leeway as `exp`; a token without one is.

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
fn future_nbf_beyond_leeway_is_refused() {
    let auth = auth();
    let now = get_current_timestamp();
    for (nbf, exp) in [
        (now + 120, None),
        (now + 3600, None),
        (now + 3600, Some(now + 7200)),
    ] {
        let mut claims = serde_json::json!({"scope": "pageserverapi", "nbf": nbf});
        if let Some(exp) = exp {
            claims["exp"] = serde_json::json!(exp);
        }
        let err = auth.decode::<Claims>(&sign(claims)).expect_err(&format!(
            "nbf {}s ahead (exp {exp:?}) is refused",
            nbf - now
        ));
        assert!(err.0.contains("ImmatureSignature"), "nbf {nbf}: {err}");
    }
}

#[test]
fn past_or_absent_nbf_and_nbf_within_leeway_are_accepted() {
    let auth = auth();
    let now = get_current_timestamp();
    for nbf in [Some(now - 3600), Some(now), Some(now + 30), None] {
        let mut claims = serde_json::json!({"scope": "metrics"});
        if let Some(nbf) = nbf {
            claims["nbf"] = serde_json::json!(nbf);
        }
        let data = auth
            .decode::<Claims>(&sign(claims))
            .unwrap_or_else(|e| panic!("nbf {nbf:?} (now {now}) is accepted: {e}"));
        assert_eq!(data.claims.scope, Scope::Metrics);
    }
}
