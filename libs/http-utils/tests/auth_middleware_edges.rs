//! Edges of the auth middleware's `metrics` rule (K7 fix round): with auth off, or on a
//! public route (no key set for it), the middleware checks nothing, so a `metrics` token
//! changes nothing there; a path that only looks like `/metrics` stays refused; the
//! token errors (missing, malformed, invalid) keep their statuses.

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;

use http_utils::RequestServiceBuilder;
use http_utils::endpoint::{auth_middleware, make_router};
use http_utils::error::ApiError;
use hyper0::service::Service;
use hyper0::{Body, Method, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use utils::auth::{JwtAuth, SwappableJwtAuth};

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

const PUBLIC: &str = "/v1/status";

fn keys() -> &'static SwappableJwtAuth {
    static AUTH: OnceLock<SwappableJwtAuth> = OnceLock::new();
    AUTH.get_or_init(|| {
        SwappableJwtAuth::new(JwtAuth::new(vec![
            DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap(),
        ]))
    })
}

/// Auth on, with `PUBLIC` left open (as the servers' `PUBLIC_ROUTES`).
fn auth_on(req: &Request<Body>) -> Option<&SwappableJwtAuth> {
    if req.uri().path() == PUBLIC {
        None
    } else {
        Some(keys())
    }
}

/// Auth off: no key set for any request.
fn auth_off(_req: &Request<Body>) -> Option<&SwappableJwtAuth> {
    None
}

async fn ok_handler(_req: Request<Body>) -> Result<Response<Body>, ApiError> {
    Ok(Response::new(Body::from("ok")))
}

fn sign(claims: serde_json::Value) -> String {
    jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &EncodingKey::from_ed_pem(TEST_PRIV_KEY_ED25519.as_bytes()).unwrap(),
    )
    .unwrap()
}

async fn call(
    provide_auth: fn(&Request<Body>) -> Option<&SwappableJwtAuth>,
    uri: &str,
    authorization: Option<&str>,
) -> StatusCode {
    let router = make_router()
        .middleware(auth_middleware(provide_auth))
        .get("/metrics", ok_handler)
        .get(PUBLIC, ok_handler)
        .get("/v1/tenant/:tenant_id", ok_handler)
        .build()
        .unwrap();
    let builder = RequestServiceBuilder::new(router).unwrap();
    let mut service = builder.build(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80));
    poll_fn(|ctx| service.poll_ready(ctx)).await.unwrap();

    let mut req = Request::builder().method(Method::GET).uri(uri);
    if let Some(value) = authorization {
        req = req.header("Authorization", value);
    }
    service
        .call(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

const TENANT_ROUTE: &str = "/v1/tenant/1a2b3344556677881122334455667788";

#[tokio::test]
async fn auth_off_lets_every_token_and_no_token_through() {
    let bearer = format!("Bearer {}", sign(serde_json::json!({"scope": "metrics"})));
    for uri in [TENANT_ROUTE, "/metrics", PUBLIC] {
        assert_eq!(
            call(auth_off, uri, Some(&bearer)).await,
            StatusCode::OK,
            "{uri}"
        );
        assert_eq!(call(auth_off, uri, None).await, StatusCode::OK, "{uri}");
    }
}

#[tokio::test]
async fn public_route_takes_a_metrics_token_or_none() {
    let bearer = format!("Bearer {}", sign(serde_json::json!({"scope": "metrics"})));
    assert_eq!(call(auth_on, PUBLIC, Some(&bearer)).await, StatusCode::OK);
    assert_eq!(call(auth_on, PUBLIC, None).await, StatusCode::OK);
}

#[tokio::test]
async fn paths_that_only_look_like_metrics_are_refused() {
    let bearer = format!("Bearer {}", sign(serde_json::json!({"scope": "metrics"})));
    for uri in [
        &format!("{TENANT_ROUTE}?path=/metrics") as &str,
        "/metrics/../v1/tenant/1a2b3344556677881122334455667788",
        "//metrics",
        "/metrics%2F",
        "/v1/status/../../metrics/x",
    ] {
        assert_eq!(
            call(auth_on, uri, Some(&bearer)).await,
            StatusCode::FORBIDDEN,
            "{uri}"
        );
    }
}

#[tokio::test]
async fn token_errors_keep_their_statuses() {
    let metrics = sign(serde_json::json!({"scope": "metrics"}));
    // No header: 401, on `/metrics` too.
    assert_eq!(
        call(auth_on, "/metrics", None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(auth_on, TENANT_ROUTE, None).await,
        StatusCode::UNAUTHORIZED
    );
    // Not a bearer token: 401.
    assert_eq!(
        call(auth_on, "/metrics", Some(&format!("Basic {metrics}"))).await,
        StatusCode::UNAUTHORIZED
    );
    // A bad signature or an expired token: 403.
    let (signed, signature) = metrics.rsplit_once('.').unwrap();
    let first = if signature.starts_with('A') { 'B' } else { 'A' };
    let tampered = format!("Bearer {signed}.{first}{}", &signature[1..]);
    assert_eq!(
        call(auth_on, "/metrics", Some(&tampered)).await,
        StatusCode::FORBIDDEN
    );
    let expired = sign(serde_json::json!({"scope": "metrics", "exp": 1_000_000_000}));
    assert_eq!(
        call(auth_on, "/metrics", Some(&format!("Bearer {expired}"))).await,
        StatusCode::FORBIDDEN
    );
    // An unknown scope doesn't decode: 403.
    let unknown = sign(serde_json::json!({"scope": "metrics-and-more"}));
    assert_eq!(
        call(auth_on, "/metrics", Some(&format!("Bearer {unknown}"))).await,
        StatusCode::FORBIDDEN
    );
}
