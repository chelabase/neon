//! compute_ctl's JWKS verification (`http/middleware/authorize.rs`) across the
//! `jsonwebtoken` 9 -> 11 move, driven through the real external router:
//!
//! - A two-key JWKS accepts a token signed by either key, in either order, whatever
//!   `kid` the token's header names; a third key's token is refused (key rotation, #6).
//! - The RS256 (Hadron) path: a JWKS holding an RS256 key verifies RS256 tokens only.
//!   Its key accepts, another RSA key, an EdDSA token and HS256 keyed with the modulus are
//!   refused. A set mixing Ed25519 and RS256 keys switches the whole set to RS256.
//! - An expired token is refused (60 s leeway), and so is an `exp` that isn't a number
//!   (it would never expire).

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use axum::Router;
use axum::body::Body;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use compute_api::responses::{ComputeConfig, ComputeCtlConfig, ComputeStatus};
use compute_tools::compute::{ComputeNode, ComputeNodeParams};
use compute_tools::http::server::Server;
use compute_tools::token_file::{INTERNAL_API_TOKEN_FILE, STORAGE_AUTH_TOKEN_FILE};
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse, RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

const COMPUTE_ID: &str = "compute-jwks";
const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");

/// RSA test keys (openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048).
const RSA_A_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCd+Q6kqBvBpUhQ
s3drNvsNHhhcWcb04hHF4tYn/26f5sZqN4LCD1+GblLzegb4SZhlTHUmQWn8+4eY
3yZim+hZZuXzO2X2inFiplcVksirjFK1GHvyKdz+EXok/FpknosUBizsRQcsIF9G
eDP7GJ0tD68Wm6dMnp6daq/Jj6vLE7912+aa3zRb84RR5jRI+XjsiXzJe7Nn3ILj
Ek40Dr7KYrxhWvnhLZR73oeFBzqj5pBJEUdngmOsIGNSIMyfOnQKv02jpnQVAQ+W
joA0sXdXqSPsCN8CGJniywEQXptIWStJs1POuBBwhAoS0YE3/0X1ANLDrQo23Zsh
zvXgXS43AgMBAAECggEANk5Tr9wQqqnIqeGAOI3OkSxa4IiGYlHDHV2FFHv1iie5
5vLNUywYwSx0/Lli4wDd0FkP3sZXCr5nV3DDD9wb7Hv4qfyt6SqfnvOi9UogDQUw
u4u+tDma/IaCkGtmIbf1BL24vMJgHFXGmwGgkP3drot5O9LnmOngiioOY0KuIqHM
2Ha3rOtLYHoKMlxAD0qZWXzGQVVR5cUnJoKu09g3AUXWmGg1ynCXbGKRCLmed2Cp
b+7kbNGuhX0pxKPDnUVsO557bVGXDTdccp9nPxm6SWP6LB2r3Ikg0NjU6qNex1k+
jUP8Gih3VwBU0KMhYnY28pHVRu+BOWm8g8ITcebFvQKBgQDeLXYtnhKWuOn3gfNx
Jz2dQ4g/gH0YVC3QNFGt/JQJHTyblEw/QlpQu7+TTek9yEquQyQleB7iZBL4dmO8
J4NV8GXNBxjekmTBL2SiQzfL8OBddc/ebpUsWy/q5xst45U+rXzQqQZBl6CjYkPy
U/WpAnkqxJBWLsAL8usU4UzLhQKBgQC2BXU5xdfSZyrQGrpegd+TXllsh+A5d/5L
vR9pQRA9vzqjvnm5rPNdyHkF0w8/dh6xyWGR0Tr7KdeTwW7fm1rEB2ZKcPcBLm3+
tx1NFWNQeXHfCHElgNPGxigi/X75thm+WJvr/DgiYb2pUmr1PDTpkGWaejKDMeoN
XMFg/mcJiwKBgCTfzLZjfthPFl3CzqGgDqTUOX+4lop8JiJhHJFQ00zz8kQsB7+U
BqNRlckf7C8Z1/M2J4CkgBO44kEkfQcUU8LmpC60F9eQ2nIJqJ0ZpOAPOV2pmPdk
yRNUiw5kjuk91V5Sst16wBQQ01NqkrZcYvBK/cswVnhHSA5zobqUbgd1AoGBAJjw
eRDz9WWqncSB0Lp78XmHuyd/+50N/7Nv0ybDLnxTY1gWQX0Lnujb+yQztQojm6LS
jJLS9PX4sFRMIXbsuBUiCobd6A0sD+wHvCz6nZoOkOlP1JIobskD0tGjob77jSHs
ngZoxFnPOmc9AvXPgr4FP/nOVwb5N6nGmA2BdN4FAoGAA1Eo7F70VRwIrN9lWPQx
E5l1sdvcqnG2nnzJM2/nCZlIdNXZ6nZ3IXfvffTzsjrGT/g2ibLQDn/ME7A5l3jR
mgO81DN701k089zu7IwrrxoaEG6gt0cZU0oNpha8Wy6w4IMy1a5RTy8VjLYxQOJk
9pwkfo3zTYaua1gf5vSJU4U=
-----END PRIVATE KEY-----
";
const RSA_A_N: &str = "nfkOpKgbwaVIULN3azb7DR4YXFnG9OIRxeLWJ_9un-bGajeCwg9fhm5S83oG-EmYZUx1JkFp_PuHmN8mYpvoWWbl8ztl9opxYqZXFZLIq4xStRh78inc_hF6JPxaZJ6LFAYs7EUHLCBfRngz-xidLQ-vFpunTJ6enWqvyY-ryxO_ddvmmt80W_OEUeY0SPl47Il8yXuzZ9yC4xJONA6-ymK8YVr54S2Ue96HhQc6o-aQSRFHZ4JjrCBjUiDMnzp0Cr9No6Z0FQEPlo6ANLF3V6kj7AjfAhiZ4ssBEF6bSFkrSbNTzrgQcIQKEtGBN_9F9QDSw60KNt2bIc714F0uNw";
const RSA_B_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhRbcDJx+MPGQR
gLb+r0u63K10vec93ihbVf55iqhddEjXljvdqv5m4O+H1VPJ91VvVuw85ze4LgV0
W0l5h4mEfP0JKSG7mSKr5taFx74GyQalaCnC68w17gPXF0kNCwHASw/uWOhzPl+V
vnODZt2oB6xTggO3yYrnufUU5RRNZjZDNjpa/N/yUBSazAnN3pM69HVP0jB8w2TL
NJc1R4kEaIG6t35H1TOitucZfRxAG5RrKFF4EVRHJruBoBp6U/egjAi/BJW6Rqp9
hnOymOcGf+GuGUt/DIVWVbkwzrLPJfnen8a9NMqMPoUsetRmtNoYaJlJvQtoBMPm
vUVHTq8LAgMBAAECggEALgMZUHGLRg+HuPN7bSXM6Avu+etX8hEQWSeFZLnnjb8U
qcQr0ij88XJ8OlheVuBH+QfeFMp9XQc5YfzLUyFV+1O0M0zNcQ3kQQxTQNv9elFR
JDPUY9XZziIhcqt05k8bOnWaeWp7gB57U5Ck82/tUkbO8feaXs2xq4cWAgCQVwZp
aON6xe9JCA9cCOW4dQCHNww0rfhXMdTjJ2Fu2JuPpx/BY+450UlCaq+wOsyAQ1UL
XFePJKnrPr7dyCxr/l71ABhYow4ceupnrXKVitPHO8swsOu/IyJB4jSc0RPxfUry
8m3IgtsiU1jRPw3BYovUelPH+zUbTfpRIRQiqYHpcQKBgQD2UtNPmUKfynrzwThU
oKXglcx3OtZ9Hf9UWyrQ+R7J4oJaZpALclD9GmqJ8VH2xD7whvToa/hVbSkun50S
TXp2fCJGvcCdVDrhWXDbFyqPrTie787rSJewq7Mrl1fFLru7EoXTj7KmV5gTtzWh
vkXMl45KRwONomXqnt9cPwGiFQKBgQDqHy+htmedTeH6Z6NdJu4II7ujd4f5tOaf
VJo8dizLx5rLHdkU09nlchymZO6dx6VvCwtMDOFr7Lry6Tyre5/Mgr9YS9/1Ua5B
eZDQsPpoVuYZZOT6Ej8IhfHcoK3Xw0omXjyMFa+ikiWcCBa3kTGHZk2VwJJGv9Bc
JE81YlP0nwKBgEAAHS9dXtYtwex7k6tJYlAMG+gOvZQcqy670VAiqkFCPSRH6b1P
ooNgzbWxod4/9yp/pjqNcySfDEg06JbM0rjeX/mJa/Z04CeVGaGTT1etZjzFijnP
zrn0osT8ua1eCyD8GxFxELXvpG/a9nBkA7a42huqf93ZCCoBxX8uT7pRAoGAHEsI
hpJ0kx4GYSyFIYzC11j6JBcd559k/3xJ52SgpT/KBSHmSg4QFxpjO/iWnZqy82hy
RQ6Jb3F8Zj6phk+6UAy88v64Yf0tAdyfE5lPqaxWwlrfERmDZJRLVk5Us+51140r
5AH657qhsOmJVUXGpoZGegJ7qvEjTP9WUy0+2CECgYEAxJ0qBbkJCeOjQXnVOGAx
tUXdk1h3tDz918mucN+4OvIXYPJLVwThQD2DIo2D76oxjr5DUx4F+OvELc4GJE/g
NI9RVQH3rbLG5vpqHb3zlqj8oHgt0g9rN7/rzV9sNANyZTXE9raDJrNYjF0x7Whk
QwocpGhU40P3YMTW3niIo3M=
-----END PRIVATE KEY-----
";

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn params(dir: &Path) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: COMPUTE_ID.into(),
        // Port 1: nothing listens, so a route that gets as far as SQL fails fast.
        connstr: url::Url::parse("postgresql://cloud_admin@127.0.0.1:1/postgres").unwrap(),
        privileged_role_name: "neon_superuser".into(),
        resize_swap_on_bind: false,
        set_disk_quota_for_fs: None,
        pgdata: dir.join("pgdata").to_string_lossy().into(),
        pgbin: "/nonexistent/postgres".into(),
        pgversion: "17".into(),
        external_http_port: 3080,
        internal_http_port: 3081,
        remote_ext_base_url: None,
        installed_extensions_collection_interval: Arc::new(AtomicU64::new(0)),
        instance_id: None,
        pg_init_timeout: None,
        pg_isready_bin: "/nonexistent/pg_isready".into(),
        lakebase_mode: false,
        build_tag: "test".into(),
        control_plane_uri: None,
        config_path_test_only: None::<OsString>,
        internal_api_token_file: dir.join(INTERNAL_API_TOKEN_FILE),
        storage_auth_token_file: dir.join(STORAGE_AUTH_TOKEN_FILE),
    }
}

fn common(kid: &str, alg: KeyAlgorithm) -> CommonParameters {
    CommonParameters {
        public_key_use: Some(PublicKeyUse::Signature),
        key_operations: None,
        key_algorithm: Some(alg),
        key_id: Some(kid.to_owned()),
        x509_url: None,
        x509_chain: None,
        x509_sha1_fingerprint: None,
        x509_sha256_fingerprint: None,
    }
}

/// A signing key, the algorithm it signs with and its JWK.
struct Key {
    alg: Algorithm,
    encoding: EncodingKey,
    jwk: Jwk,
}

fn ed_key(kid: &str) -> Key {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    Key {
        alg: Algorithm::EdDSA,
        encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
        jwk: Jwk {
            common: common(kid, KeyAlgorithm::EdDSA),
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: BASE64_URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            }),
        },
    }
}

fn rsa_jwk(kid: &str, n: &str) -> Jwk {
    Jwk {
        common: common(kid, KeyAlgorithm::RS256),
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: n.into(),
            e: "AQAB".into(),
        }),
    }
}

/// RSA key A (in the JWKS as `rsa-a`).
fn rsa_a() -> Key {
    Key {
        alg: Algorithm::RS256,
        encoding: EncodingKey::from_rsa_pem(RSA_A_PEM.as_bytes()).unwrap(),
        jwk: rsa_jwk("rsa-a", RSA_A_N),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn jwt_with(alg: Algorithm, encoding: &EncodingKey, kid: Option<&str>, claims: &Value) -> String {
    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_owned);
    jsonwebtoken::encode(&header, claims, encoding).unwrap()
}

fn jwt(key: &Key, claims: &Value) -> String {
    jwt_with(
        key.alg,
        &key.encoding,
        key.jwk.common.key_id.as_deref(),
        claims,
    )
}

fn control_claims() -> Value {
    json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 })
}

/// A running compute's external router, trusting `keys`.
fn external(dir: &Path, keys: Vec<Jwk>) -> Router {
    let jwks = JwkSet { keys };
    let spec = {
        let mut json: Value = serde_json::from_str(SPEC).unwrap();
        json["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
        json.as_object_mut().unwrap().remove("storage_auth_token");
        serde_json::from_value(json).unwrap()
    };
    let compute = ComputeNode::new(
        params(dir),
        ComputeConfig {
            spec: Some(spec),
            compute_ctl_config: ComputeCtlConfig {
                jwks: jwks.clone(),
                tls: None,
            },
        },
    )
    .unwrap();
    compute.set_status(ComputeStatus::Running);
    Router::from(&Server::External {
        port: 3080,
        config: ComputeCtlConfig { jwks, tls: None },
        compute_id: COMPUTE_ID.into(),
        instance_id: None,
    })
    .with_state(Arc::new(compute))
}

/// The status of `GET /status` with `token` as the bearer.
async fn status(router: &Router, token: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/status")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = tokio::time::timeout(Duration::from_secs(20), router.clone().oneshot(req))
        .await
        .expect("the route answered within 20 s")
        .unwrap();
    let status = res.status();
    let _ = res.into_body().collect().await;
    status
}

#[tokio::test]
async fn a_two_key_jwks_accepts_either_key_and_refuses_a_third() {
    let dir = fresh("jwks_two_keys");
    let (a, b, c) = (ed_key("a"), ed_key("b"), ed_key("c"));
    for keys in [
        vec![a.jwk.clone(), b.jwk.clone()],
        vec![b.jwk.clone(), a.jwk.clone()],
    ] {
        let router = external(&dir, keys);
        for (name, key) in [("a", &a), ("b", &b)] {
            assert_eq!(
                status(&router, &jwt(key, &control_claims())).await,
                StatusCode::OK,
                "key {name}"
            );
        }
        assert_eq!(
            status(&router, &jwt(&c, &control_claims())).await,
            StatusCode::UNAUTHORIZED,
            "a third key"
        );
        // The header's `kid` picks nothing: every key of the set is tried.
        for kid in [Some("b"), Some("nope"), None] {
            let token = jwt_with(Algorithm::EdDSA, &a.encoding, kid, &control_claims());
            assert_eq!(status(&router, &token).await, StatusCode::OK, "kid {kid:?}");
            let token = jwt_with(Algorithm::EdDSA, &c.encoding, kid, &control_claims());
            assert_eq!(
                status(&router, &token).await,
                StatusCode::UNAUTHORIZED,
                "a third key, kid {kid:?}"
            );
        }
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_rs256_path_verifies_rs256_only() {
    let dir = fresh("jwks_rs256");
    let a = rsa_a();
    let router = external(&dir, vec![a.jwk.clone()]);
    assert_eq!(
        status(&router, &jwt(&a, &control_claims())).await,
        StatusCode::OK
    );

    let b = EncodingKey::from_rsa_pem(RSA_B_PEM.as_bytes()).unwrap();
    let ed = ed_key("rsa-a");
    let n = BASE64_URL_SAFE_NO_PAD.decode(RSA_A_N).unwrap();
    for (name, token) in [
        (
            "another RSA key",
            jwt_with(Algorithm::RS256, &b, Some("rsa-a"), &control_claims()),
        ),
        ("an EdDSA token", jwt(&ed, &control_claims())),
        (
            "HS256 keyed with the modulus",
            jwt_with(
                Algorithm::HS256,
                &EncodingKey::from_secret(&n),
                Some("rsa-a"),
                &control_claims(),
            ),
        ),
        (
            "HS256 keyed with the JWK's n",
            jwt_with(
                Algorithm::HS256,
                &EncodingKey::from_secret(RSA_A_N.as_bytes()),
                Some("rsa-a"),
                &control_claims(),
            ),
        ),
    ] {
        assert_eq!(
            status(&router, &token).await,
            StatusCode::UNAUTHORIZED,
            "{name}"
        );
    }

    // One RS256 key switches the set to RS256: its Ed25519 key no longer verifies.
    let router = external(&dir, vec![ed.jwk.clone(), a.jwk.clone()]);
    assert_eq!(
        status(&router, &jwt(&a, &control_claims())).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&router, &jwt(&ed, &control_claims())).await,
        StatusCode::UNAUTHORIZED,
        "EdDSA in a set with an RS256 key"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn expiry_is_checked_and_a_non_numeric_exp_is_refused() {
    let dir = fresh("jwks_expiry");
    let a = ed_key("a");
    let router = external(&dir, vec![a.jwk.clone()]);
    let now = now();
    for exp in [json!(now - 120), json!(1)] {
        let claims = json!({ "compute_id": COMPUTE_ID, "exp": exp });
        assert_eq!(
            status(&router, &jwt(&a, &claims)).await,
            StatusCode::UNAUTHORIZED,
            "exp {exp}"
        );
    }
    for exp in [json!(now - 30), json!(now + 3600), Value::Null] {
        let mut claims = json!({ "compute_id": COMPUTE_ID });
        if !exp.is_null() {
            claims["exp"] = exp.clone();
        }
        assert_eq!(
            status(&router, &jwt(&a, &claims)).await,
            StatusCode::OK,
            "exp {exp}"
        );
    }
    // An `exp` that isn't a NumericDate would never expire.
    for exp in [json!((now - 3600).to_string()), json!(-1), Value::Null] {
        let claims = json!({ "compute_id": COMPUTE_ID, "exp": exp });
        assert_eq!(
            status(&router, &jwt(&a, &claims)).await,
            StatusCode::UNAUTHORIZED,
            "exp {exp}"
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}
