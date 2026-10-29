//! Storage-token verification (`utils::auth::JwtAuth`, used by the pageserver and the
//! safekeeper) across the `jsonwebtoken` 9 -> 11 move:
//!
//! - Tokens minted by the v9 code (`encode_from_key_file` on `jsonwebtoken` 9.2.0, the
//!   fixtures below) get the same accept/reject result.
//! - Algorithm confusion is refused: `alg: none` (any spelling), and HS256 tokens whose
//!   HMAC secret is the EdDSA public key (as PEM, SPKI DER or the raw 32 bytes).
//! - A token signed by another key is refused, and so is an expired one (beyond the
//!   60 s leeway); one within the leeway is accepted.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, get_current_timestamp};
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

/// Another Ed25519 key, which `auth()` doesn't trust.
const OTHER_PRIV_KEY_ED25519: &str = r#"
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDnBXghIKS7Ucm892zb74I8ljv7A1d6FLOBLeuohefN9
-----END PRIVATE KEY-----
"#;

// Minted by the v9 code (`encode_from_key_file`, jsonwebtoken 9.2.0) with the test key,
// except `TENANT_OTHER_KEY` (the other key). Ed25519 signatures are deterministic, so
// the v11 code mints the same strings (checked below).
//
// {"scope":"tenant","tenant_id":"3aa8fcc61f6d357410b7de754b1d9001"}
const TENANT_NO_EXP: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzY29wZSI6InRlbmFudCIsInRlbmFudF9pZCI6IjNhYThmY2M2MWY2ZDM1NzQxMGI3ZGU3NTRiMWQ5MDAxIn0.TCSFpWHJ9nCMl8EKDnd3UqNwQtFKHi5NR-sbDHzgZwOeQFa1C-CxQ-xfwPTDrs2W2U0AG_YUXf8pS7EbMUFBAQ";
// {"exp":4102444800,"scope":"pageserverapi"}
const PAGESERVERAPI_EXP_2100: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoicGFnZXNlcnZlcmFwaSJ9.rkpmjGa5fQ5DvGXBWwxXu6dyW-BIRreblaYgORccY11Vs0TMbbYSXBvJWD4HEX3fryBg87TQK8a8oiZzwj8PBw";
// {"exp":1000000000,"scope":"safekeeperdata"}
const SAFEKEEPERDATA_EXPIRED_2001: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJleHAiOjEwMDAwMDAwMDAsInNjb3BlIjoic2FmZWtlZXBlcmRhdGEifQ.0s4lJaBNZQ3ytGXoE1EY9otRH4fagDEN37FJrJtmlsVfYHRZZ9tlOJsP24PeMNRWJbXKIQq4BqL_Pxn05RzSDQ";
// {"scope":"tenant","tenant_id":"3aa8fcc61f6d357410b7de754b1d9001"}, the other key
const TENANT_OTHER_KEY: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJzY29wZSI6InRlbmFudCIsInRlbmFudF9pZCI6IjNhYThmY2M2MWY2ZDM1NzQxMGI3ZGU3NTRiMWQ5MDAxIn0.lE-8844gbOa2hoeNYORGz9RAKCoZLuGIiq4XFhskIidosAnuSYvSJcleKkUo5LPyck0gcQMkAMjU6iYRUs9FDA";
// {"nbf":4102444800,"scope":"pageserverapi"}
const PAGESERVERAPI_NBF_2100: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJuYmYiOjQxMDI0NDQ4MDAsInNjb3BlIjoicGFnZXNlcnZlcmFwaSJ9.5H3EKItx_GZBEqKG9MvU-ncb6cxElhindfv5m8_iXC9j1PtBJgLvyHDRQNMI7Ie0DI5d2WaHJnghFJdbb970DQ";

/// `{"scope":"pageserverapi"}`, base64url.
const PAYLOAD: &str = "eyJzY29wZSI6InBhZ2VzZXJ2ZXJhcGkifQ";

fn auth() -> JwtAuth {
    JwtAuth::new(vec![
        DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap(),
    ])
}

fn sign_with(key: &str, claims: serde_json::Value) -> String {
    encode_from_key_file(&claims, &pem::parse(key).unwrap()).unwrap()
}

fn sign(claims: serde_json::Value) -> String {
    sign_with(TEST_PRIV_KEY_ED25519, claims)
}

#[test]
fn v9_fixtures_keep_their_result() {
    let auth = auth();

    let data = auth
        .decode::<Claims>(TENANT_NO_EXP)
        .expect("a tenant token without exp");
    assert_eq!(data.claims.scope, Scope::Tenant);
    assert_eq!(
        data.claims.tenant_id.unwrap().to_string(),
        "3aa8fcc61f6d357410b7de754b1d9001"
    );
    assert_eq!(data.header.alg, Algorithm::EdDSA);

    let data = auth
        .decode::<Claims>(PAGESERVERAPI_EXP_2100)
        .expect("a token expiring in 2100");
    assert_eq!(data.claims.scope, Scope::PageServerApi);

    for (name, token, want) in [
        (
            "expired in 2001",
            SAFEKEEPERDATA_EXPIRED_2001,
            "ExpiredSignature",
        ),
        ("another key", TENANT_OTHER_KEY, "InvalidSignature"),
        ("nbf in 2100", PAGESERVERAPI_NBF_2100, "ImmatureSignature"),
    ] {
        let err = auth
            .decode::<Claims>(token)
            .expect_err(&format!("{name} is refused"));
        assert!(err.0.contains(want), "{name}: {err}");
    }
}

/// The signing side is unchanged too: today's code mints the v9 strings byte for byte.
#[test]
fn today_mints_the_v9_fixtures() {
    let tenant =
        serde_json::json!({"scope": "tenant", "tenant_id": "3aa8fcc61f6d357410b7de754b1d9001"});
    assert_eq!(sign(tenant.clone()), TENANT_NO_EXP);
    assert_eq!(sign_with(OTHER_PRIV_KEY_ED25519, tenant), TENANT_OTHER_KEY);
    assert_eq!(
        sign(serde_json::json!({"scope": "pageserverapi", "exp": 4102444800u64})),
        PAGESERVERAPI_EXP_2100
    );
}

#[test]
fn alg_none_is_refused() {
    let auth = auth();
    for header in [
        // {"alg":"none","typ":"JWT"}
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
        // {"alg":"None","typ":"JWT"}
        "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0",
        // {"typ":"JWT"}: no alg at all
        "eyJ0eXAiOiJKV1QifQ",
    ] {
        let real_signature = sign(serde_json::json!({"scope": "pageserverapi"}));
        let real_signature = real_signature.rsplit('.').next().unwrap();
        for token in [
            format!("{header}.{PAYLOAD}."),
            format!("{header}.{PAYLOAD}"),
            format!("{header}.{PAYLOAD}.{real_signature}"),
        ] {
            auth.decode::<Claims>(&token)
                .expect_err(&format!("{token} is refused"));
        }
    }
}

#[test]
fn hs256_with_the_public_key_as_secret_is_refused() {
    let auth = auth();
    let pem_text = TEST_PUB_KEY_ED25519.as_bytes();
    let spki_der = pem::parse(TEST_PUB_KEY_ED25519).unwrap().into_contents();
    let raw = spki_der[spki_der.len() - 32..].to_vec();
    let trimmed = TEST_PUB_KEY_ED25519.trim().as_bytes();
    for (name, secret) in [
        ("PEM text", pem_text),
        ("trimmed PEM text", trimmed),
        ("SPKI DER", &spki_der[..]),
        ("raw key", &raw[..]),
    ] {
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            let token = jsonwebtoken::encode(
                &Header::new(alg),
                &serde_json::json!({"scope": "pageserverapi"}),
                &EncodingKey::from_secret(secret),
            )
            .unwrap();
            let err = auth
                .decode::<Claims>(&token)
                .expect_err(&format!("{alg:?} keyed with the {name} is refused"));
            assert!(err.0.contains("InvalidAlgorithm"), "{alg:?}, {name}: {err}");
        }
    }
}

#[test]
fn wrong_key_is_refused() {
    let err = auth()
        .decode::<Claims>(&sign_with(
            OTHER_PRIV_KEY_ED25519,
            serde_json::json!({"scope": "pageserverapi", "exp": get_current_timestamp() + 3600}),
        ))
        .expect_err("another key's token");
    assert!(err.0.contains("InvalidSignature"), "{err}");
}

#[test]
fn expiry_keeps_the_60_s_leeway() {
    let auth = auth();
    let now = get_current_timestamp();
    for exp in [now - 61 - 5, now - 3600, 1] {
        let err = auth
            .decode::<Claims>(&sign(serde_json::json!({"scope": "metrics", "exp": exp})))
            .expect_err(&format!("exp {exp} (now {now}) is refused"));
        assert!(err.0.contains("ExpiredSignature"), "exp {exp}: {err}");
    }
    for exp in [now - 30, now, now + 3600] {
        auth.decode::<Claims>(&sign(serde_json::json!({"scope": "metrics", "exp": exp})))
            .unwrap_or_else(|e| panic!("exp {exp} (now {now}) is accepted: {e}"));
    }
}

/// `aud`, `iss` and `sub` aren't checked on storage tokens (no audience is configured,
/// and a token that carries one is refused: the library rejects an `aud` it wasn't told
/// to expect).
#[test]
fn audience_on_a_storage_token_is_refused() {
    let auth = auth();
    for aud in [
        serde_json::json!("pageserver"),
        serde_json::json!(["x"]),
        serde_json::json!([]),
    ] {
        let err = auth
            .decode::<Claims>(&sign(serde_json::json!({"scope": "metrics", "aud": aud})))
            .expect_err(&format!("aud {aud} is refused"));
        assert!(err.0.contains("InvalidAudience"), "aud {aud}: {err}");
    }
    auth.decode::<Claims>(&sign(
        serde_json::json!({"scope": "metrics", "iss": "anyone", "sub": "anything"}),
    ))
    .expect("iss and sub are not checked");
}

/// With several keys, a token with a malformed `exp` signed by any of them is refused
/// as such, whichever position its key has (the signing key verified it).
#[test]
fn malformed_exp_is_refused_whatever_the_key_order() {
    let test = || DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap();
    let other = || {
        DecodingKey::from_ed_pem(
            b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEATmtUhuU3zEY3TKl3Tqgg1moe3VLZupDTz3I2315zbX4=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap()
    };
    let token = sign(serde_json::json!({"scope": "metrics", "exp": "4102444800"}));
    for keys in [vec![test(), other()], vec![other(), test()]] {
        let err = JwtAuth::new(keys)
            .decode::<Claims>(&token)
            .expect_err("a string exp is refused");
        assert!(err.0.contains("NumericDate"), "{err}");
    }
}
