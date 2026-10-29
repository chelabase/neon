//! endpoint_storage's token check (`endpoint_storage::JwtAuth`) across the
//! `jsonwebtoken` 9 -> 11 move: tokens minted by the v9 code keep their result, `exp`
//! stays required, and algorithm confusion (`alg: none`, HS256 keyed with the public
//! key) is refused.

use endpoint_storage::JwtAuth;
use endpoint_storage::claims::EndpointStorageClaims;
use jsonwebtoken::{Algorithm, EncodingKey, Header};

// The test key pair of `app.rs`'s tests.
const TEST_PUB_KEY_ED25519: &[u8] = b"
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARYwaNBayR+eGI0iXB4s3QxE3Nl2g1iWbr6KtLWeVD/w=
-----END PUBLIC KEY-----
";

// Minted by the v9 code (jsonwebtoken 9.2.0, `Header::new(EdDSA)`) with the test key,
// except `ES_OTHER_KEY`. Claims: tenant 00010203040506070809010203040506, timeline
// 00010203040506070809010203040507, endpoint ep-winter-frost-a662z3vg, and:
//
// exp 4102444800 (2100)
const ES_EXP_2100: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJlbmRwb2ludF9pZCI6ImVwLXdpbnRlci1mcm9zdC1hNjYyejN2ZyIsImV4cCI6NDEwMjQ0NDgwMCwidGVuYW50X2lkIjoiMDAwMTAyMDMwNDA1MDYwNzA4MDkwMTAyMDMwNDA1MDYiLCJ0aW1lbGluZV9pZCI6IjAwMDEwMjAzMDQwNTA2MDcwODA5MDEwMjAzMDQwNTA3In0.TSp79fKaH3MRb27fSrwv9ELQ5JDDE5YdkBh2SV7gDAwis14jbzz_8e4Lx952R71q8AsqEgVC98vb7tnvzo_CDg";
// exp 1000000000 (2001)
const ES_EXPIRED_2001: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJlbmRwb2ludF9pZCI6ImVwLXdpbnRlci1mcm9zdC1hNjYyejN2ZyIsImV4cCI6MTAwMDAwMDAwMCwidGVuYW50X2lkIjoiMDAwMTAyMDMwNDA1MDYwNzA4MDkwMTAyMDMwNDA1MDYiLCJ0aW1lbGluZV9pZCI6IjAwMDEwMjAzMDQwNTA2MDcwODA5MDEwMjAzMDQwNTA3In0.IV_arKMwbSQViIn3wtGTb1WhcKb0JUN3fyg1uhtOPyYBYChYPYV4Ej8SmIeA26fzOdh5oKt2icwThGDgvPl0Cg";
// no exp
const ES_NO_EXP: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJlbmRwb2ludF9pZCI6ImVwLXdpbnRlci1mcm9zdC1hNjYyejN2ZyIsInRlbmFudF9pZCI6IjAwMDEwMjAzMDQwNTA2MDcwODA5MDEwMjAzMDQwNTA2IiwidGltZWxpbmVfaWQiOiIwMDAxMDIwMzA0MDUwNjA3MDgwOTAxMDIwMzA0MDUwNyJ9.FtmvDBXWHGqc_H145lI0mTr9PDw_JIS1W4X-Nh1I5v0pPh_WpV3MiXGvZ0jAd0X4r7Nnv7oqk4WGjGzjibSiDw";
// exp 4102444800, signed by another key
const ES_OTHER_KEY: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJlbmRwb2ludF9pZCI6ImVwLXdpbnRlci1mcm9zdC1hNjYyejN2ZyIsImV4cCI6NDEwMjQ0NDgwMCwidGVuYW50X2lkIjoiMDAwMTAyMDMwNDA1MDYwNzA4MDkwMTAyMDMwNDA1MDYiLCJ0aW1lbGluZV9pZCI6IjAwMDEwMjAzMDQwNTA2MDcwODA5MDEwMjAzMDQwNTA3In0.3sOaC4ysxQmzKhcu8kf55MfsInCN_RtWZsMUAfnmi6FsX-KTcxIEedMMYNEkJM4Y-v1Ad8_esASNot6KErhMBA";

fn auth() -> JwtAuth {
    JwtAuth::new(TEST_PUB_KEY_ED25519).unwrap()
}

fn error(token: &str) -> String {
    match auth().decode::<EndpointStorageClaims>(token) {
        Ok(claims) => panic!("accepted: {claims}"),
        Err(e) => format!("{e:#}"),
    }
}

#[test]
fn v9_fixtures_keep_their_result() {
    let claims = auth()
        .decode::<EndpointStorageClaims>(ES_EXP_2100)
        .expect("a token expiring in 2100");
    assert_eq!(claims.exp, 4102444800);
    assert_eq!(
        claims.tenant_id.to_string(),
        "00010203040506070809010203040506"
    );
    assert_eq!(
        claims.timeline_id.to_string(),
        "00010203040506070809010203040507"
    );
    assert_eq!(claims.endpoint_id.to_string(), "ep-winter-frost-a662z3vg");

    for (name, token, want) in [
        ("expired in 2001", ES_EXPIRED_2001, "ExpiredSignature"),
        // The claims fail to deserialize before validation looks for `exp`.
        ("no exp", ES_NO_EXP, "missing field `exp`"),
        ("another key", ES_OTHER_KEY, "InvalidSignature"),
    ] {
        let err = error(token);
        assert!(err.contains(want), "{name}: {err}");
    }
}

#[test]
fn alg_none_and_hs256_with_the_public_key_are_refused() {
    let (header, rest) = ES_EXP_2100.split_once('.').unwrap();
    assert_eq!(header, "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9");
    let payload = rest.split_once('.').unwrap().0;
    // {"alg":"none","typ":"JWT"}
    let none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
    for token in [
        format!("{none}.{payload}."),
        format!("{none}.{payload}"),
        format!("{none}.{rest}"),
    ] {
        error(&token);
    }

    let claims: serde_json::Value = serde_json::json!({
        "tenant_id": "00010203040506070809010203040506",
        "timeline_id": "00010203040506070809010203040507",
        "endpoint_id": "ep-winter-frost-a662z3vg",
        "exp": 4102444800u64,
    });
    // The public key as SPKI DER; its last 32 bytes are the raw key.
    let spki_der: [u8; 44] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x45, 0x8c, 0x1a,
        0x34, 0x16, 0xb2, 0x47, 0xe7, 0x86, 0x23, 0x48, 0x97, 0x07, 0x8b, 0x37, 0x43, 0x11, 0x37,
        0x36, 0x5d, 0xa0, 0xd6, 0x25, 0x9b, 0xaf, 0xa2, 0xad, 0x2d, 0x67, 0x95, 0x0f, 0xfc,
    ];
    for secret in [TEST_PUB_KEY_ED25519, &spki_der[..], &spki_der[12..]] {
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let err = error(&token);
        assert!(err.contains("InvalidAlgorithm"), "{err}");
    }
}
