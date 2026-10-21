//! The auth middleware refuses a `metrics` token on every path but `/metrics`, before any
//! handler runs (K7 fix round: the route-scope invariant's first line of defence, so a
//! handler that forgets its permission check still can't be reached with a metrics token).

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

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

const TENANT: &str = "1a2b3344556677881122334455667788";

/// Handler runs, so a test can tell "refused before the handler" from "refused by it".
static HANDLER_RUNS: AtomicUsize = AtomicUsize::new(0);

fn provide_auth(_req: &Request<Body>) -> Option<&SwappableJwtAuth> {
    static AUTH: OnceLock<SwappableJwtAuth> = OnceLock::new();
    Some(AUTH.get_or_init(|| {
        SwappableJwtAuth::new(JwtAuth::new(vec![
            DecodingKey::from_ed_pem(TEST_PUB_KEY_ED25519.as_bytes()).unwrap(),
        ]))
    }))
}

/// A handler with no permission check of its own: only the middleware stands in front.
async fn open_handler(_req: Request<Body>) -> Result<Response<Body>, ApiError> {
    HANDLER_RUNS.fetch_add(1, Ordering::SeqCst);
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

async fn call(method: Method, uri: &str, token: &str) -> (StatusCode, usize) {
    let router = make_router()
        .middleware(auth_middleware(provide_auth))
        .get("/metrics", open_handler)
        .get("/profile/cpu", open_handler)
        .get("/v1/tenant/:tenant_id", open_handler)
        .delete("/v1/tenant/:tenant_id", open_handler)
        .put("/v1/failpoints", open_handler)
        .post("/v1/tenant/:tenant_id/secondary/download", open_handler)
        .build()
        .unwrap();
    let builder = RequestServiceBuilder::new(router).unwrap();
    let mut service = builder.build(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80));
    poll_fn(|ctx| service.poll_ready(ctx)).await.unwrap();

    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let before = HANDLER_RUNS.load(Ordering::SeqCst);
    let resp = service.call(req).await.unwrap();
    (resp.status(), HANDLER_RUNS.load(Ordering::SeqCst) - before)
}

/// One test, so the handler counter isn't shared with a concurrent test.
#[tokio::test]
async fn metrics_token_is_refused_off_metrics_before_any_handler() {
    let metrics = sign(serde_json::json!({"scope": "metrics"}));
    let metrics_with_tenant = sign(serde_json::json!({"scope": "metrics", "tenant_id": TENANT}));

    let tenant_route = format!("/v1/tenant/{TENANT}");
    let download_route = format!("/v1/tenant/{TENANT}/secondary/download");
    let refused: Vec<(Method, &str)> = vec![
        (Method::GET, tenant_route.as_str()),
        (Method::DELETE, tenant_route.as_str()),
        (Method::PUT, "/v1/failpoints"),
        (Method::POST, download_route.as_str()),
        (Method::GET, "/profile/cpu"),
        // Only the exact path `/metrics` is open to the scope.
        (Method::GET, "/metrics/"),
        (Method::GET, "/metrics/x"),
        (Method::GET, "/Metrics"),
        (Method::GET, "/v1/metrics"),
        // An unknown path is refused before routing, not answered 404.
        (Method::GET, "/no/such/route"),
    ];
    for token in [&metrics, &metrics_with_tenant] {
        for (method, uri) in &refused {
            let (status, runs) = call(method.clone(), uri, token).await;
            assert_eq!(
                (status, runs),
                (StatusCode::FORBIDDEN, 0),
                "{method} {uri} with a metrics token: no handler may run"
            );
        }
    }

    // `/metrics` still takes the scope (with a query string too).
    for uri in ["/metrics", "/metrics?format=text"] {
        let (status, runs) = call(Method::GET, uri, &metrics).await;
        assert_eq!(
            (status, runs),
            (StatusCode::OK, 1),
            "GET {uri} with a metrics token"
        );
    }

    // Other scopes pass the middleware unchanged: the handlers decide.
    for scope in ["pageserverapi", "safekeeperdata", "admin"] {
        let token = sign(serde_json::json!({"scope": scope}));
        let (status, runs) = call(Method::GET, &tenant_route, &token).await;
        assert_eq!(
            (status, runs),
            (StatusCode::OK, 1),
            "GET {tenant_route} with {scope}"
        );
    }
    let tenant = sign(serde_json::json!({"scope": "tenant", "tenant_id": TENANT}));
    let (status, runs) = call(Method::GET, &tenant_route, &tenant).await;
    assert_eq!(
        (status, runs),
        (StatusCode::OK, 1),
        "GET {tenant_route} with its tenant"
    );
}
