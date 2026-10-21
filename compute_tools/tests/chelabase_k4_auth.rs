//! Fork round 4, K4: compute_ctl's external server authentication (spec §5,
//! §7's compute_ctl part: U4, S18, RT4-9; §15 RT4-10). Every test drives the
//! real external router with `oneshot`; tokens are minted from JSON claims, so
//! this file compiles before `ComputeClaimsScope::Metrics` exists.
//!
//! Pinned behaviour (the code under test, `http/middleware/authorize.rs` and
//! `http/server.rs`):
//! - A missing, malformed or non-Bearer `Authorization` header is `401` with
//!   `WWW-Authenticate: Bearer…` and a JSON `{"error": …}` body that never
//!   echoes the header. Every other `401` (bad signature, expired, bad
//!   audience) carries the same challenge; `403` (wrong or missing
//!   `compute_id`) stays.
//! - No `INSTANCE_ID` bypass: `Server::External { instance_id: Some(_) }`
//!   authenticates exactly like `None` (the field stays; `Authorize` ignores it).
//! - No bearer is ever logged; a JWK without `kid` is logged as `<no kid>` and
//!   skipped, never a panic.
//! - `GET /metrics` and `GET /autoscaling_metrics` sit behind `Authorize` and
//!   accept a `metrics` token (any or no `compute_id`, no `aud` needed), a
//!   `compute_ctl:admin` token (with `aud: ["compute"]`, as today) and this
//!   compute's control token (`{compute_id, exp}`); another compute's control
//!   token is `403`; an expired token is `401`.
//! - A `metrics` token on any other route is `403`, whatever `compute_id` it
//!   carries (RT4-9): the decision is by route (the request path), never by a
//!   prefix or the query string.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
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
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

const COMPUTE_ID: &str = "compute-k4";
const OTHER_ID: &str = "compute-k4-other";
const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn params(dir: &Path, instance_id: Option<&str>) -> ComputeNodeParams {
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
        instance_id: instance_id.map(str::to_owned),
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

/// One Ed25519 signing key and its JWK (with or without a `kid`).
struct Key {
    encoding: EncodingKey,
    jwk: Jwk,
}

fn common(kid: Option<&str>) -> CommonParameters {
    CommonParameters {
        public_key_use: Some(PublicKeyUse::Signature),
        key_operations: None,
        key_algorithm: Some(KeyAlgorithm::EdDSA),
        key_id: kid.map(str::to_owned),
        x509_url: None,
        x509_chain: None,
        x509_sha1_fingerprint: None,
        x509_sha256_fingerprint: None,
    }
}

fn new_key(kid: Option<&str>) -> Key {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    Key {
        encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
        jwk: Jwk {
            common: common(kid),
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: BASE64_URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            }),
        },
    }
}

/// A JWK `DecodingKey::from_jwk` can't build a key from (its `x` isn't base64).
fn broken_jwk(kid: Option<&str>) -> Jwk {
    Jwk {
        common: common(kid),
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: "not base64 at all!".into(),
        }),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn jwt(key: &Key, claims: Value) -> String {
    jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &key.encoding).unwrap()
}

/// A compute (status `running`) and its external router, trusting `jwks`.
fn external_with(dir: &Path, jwks: JwkSet, instance_id: Option<&str>) -> Router {
    let spec = {
        let mut json: Value = serde_json::from_str(SPEC).unwrap();
        json["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
        json.as_object_mut().unwrap().remove("storage_auth_token");
        serde_json::from_value(json).unwrap()
    };
    let compute = ComputeNode::new(
        params(dir, instance_id),
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
    let compute = Arc::new(compute);
    Router::from(&Server::External {
        port: 3080,
        config: ComputeCtlConfig { jwks, tls: None },
        compute_id: COMPUTE_ID.into(),
        instance_id: instance_id.map(str::to_owned),
    })
    .with_state(compute)
}

fn external(dir: &Path, key: &Key) -> Router {
    external_with(
        dir,
        JwkSet {
            keys: vec![key.jwk.clone()],
        },
        None,
    )
}

fn request(method: &Method, uri: &str, auth: Option<&str>) -> Request<Body> {
    let mut req = Request::builder().method(method.clone()).uri(uri);
    if let Some(auth) = auth {
        req = req.header("authorization", auth);
    }
    if *method == Method::POST {
        req.header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap()
    } else {
        req.body(Body::empty()).unwrap()
    }
}

async fn call(router: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let res = tokio::time::timeout(Duration::from_secs(20), router.clone().oneshot(req))
        .await
        .expect("the route answered within 20 s")
        .unwrap();
    let (parts, body) = res.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn assert_challenged(what: &str, status: StatusCode, headers: &HeaderMap, body: &str) {
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{what}: {body}");
    let challenge = headers
        .get("www-authenticate")
        .unwrap_or_else(|| panic!("{what}: a 401 without WWW-Authenticate"))
        .to_str()
        .unwrap();
    assert!(challenge.starts_with("Bearer"), "{what}: {challenge}");
    let json: Value =
        serde_json::from_str(body).unwrap_or_else(|_| panic!("{what}: not JSON: {body}"));
    assert!(json["error"].is_string(), "{what}: {body}");
}

/// A route was reached: auth let the request through to the handler (whose
/// own answer, e.g. `/autoscaling_metrics`' 500 without a Postgres socket, is
/// not this file's business).
fn assert_reached(what: &str, status: StatusCode, body: &str) {
    assert!(
        !matches!(
            status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST
        ),
        "{what}: refused with {status}: {body}"
    );
}

/// Everything `tracing` prints on this thread while the guard lives.
#[derive(Clone)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    fn capture() -> (Logs, tracing::subscriber::DefaultGuard) {
        let logs = Logs(Arc::new(Mutex::new(Vec::new())));
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

// ---------------------------------------------------------------------------
// The route table
// ---------------------------------------------------------------------------

/// The two metrics routes: the only ones a `metrics` token opens.
const METRICS_ROUTES: [&str; 2] = ["/metrics", "/autoscaling_metrics"];

/// Every other route of the external server, with each method it serves.
const OTHER_ROUTES: [(&str, &str); 16] = [
    ("GET", "/lfc/prewarm"),
    ("POST", "/lfc/prewarm"),
    ("DELETE", "/lfc/prewarm"),
    ("GET", "/lfc/offload"),
    ("POST", "/lfc/offload"),
    ("POST", "/promote"),
    ("POST", "/check_writability"),
    ("POST", "/configure"),
    ("GET", "/database_schema"),
    ("GET", "/dbs_and_roles"),
    ("GET", "/insights"),
    ("GET", "/metrics.json"),
    ("GET", "/status"),
    ("POST", "/storage_token"),
    ("POST", "/terminate"),
    ("GET", "/hadron_liveness_probe"),
];

/// The internal server's routes (another server, not behind `Authorize`).
const INTERNAL_ROUTES: [&str; 5] = [
    "/extension_server/{*filename}",
    "/extensions",
    "/grants",
    "/refresh_configuration",
    "/failpoints",
];

fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).unwrap()
}

/// The table above is every route `server.rs` registers: a route added later
/// must be put in it (and so gets the `metrics`-token check below).
#[test]
fn the_route_table_is_complete() {
    let source = include_str!("../src/http/server.rs");
    let mut registered = Vec::new();
    for piece in source.split(".route(").skip(1) {
        let piece = piece.trim_start();
        let path = piece
            .strip_prefix('"')
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_else(|| panic!("a .route( without a literal path: {piece:.60}"));
        registered.push(path.to_owned());
    }
    assert!(registered.len() >= 20, "{registered:?}");
    for path in &registered {
        let known = METRICS_ROUTES.contains(&path.as_str())
            || OTHER_ROUTES.iter().any(|(_, p)| p == path)
            || INTERNAL_ROUTES.contains(&path.as_str());
        assert!(
            known,
            "{path} is registered in server.rs but not in K4's route table"
        );
    }
}

// ---------------------------------------------------------------------------
// 401 for a missing or malformed bearer (spec §5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_or_malformed_bearer_is_401_with_a_challenge() {
    let dir = fresh("k4_auth_missing");
    let key = new_key(Some("k4"));
    let router = external(&dir, &key);
    let good = jwt(
        &key,
        json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 }),
    );
    let presented: Vec<Option<String>> = vec![
        None,
        Some("Basic Zm9vOmJhcg==".into()),
        Some("Bearer".into()),
        Some("Bearer ".into()),
        Some(format!("Token {good}")),
        Some(good.clone()),
        Some(format!("Bearer {good} {good}")),
        Some("Bearer k4needle.not.ajwt".into()),
    ];
    let mut routes: Vec<(Method, &str)> =
        METRICS_ROUTES.iter().map(|r| (Method::GET, *r)).collect();
    routes.extend(OTHER_ROUTES.iter().map(|(m, r)| (method(m), *r)));
    for (m, route) in &routes {
        for auth in &presented {
            let shown = auth.as_deref().unwrap_or("<none>");
            let (status, headers, text) = call(&router, request(m, route, auth.as_deref())).await;
            assert_challenged(
                &format!("{m} {route} with {shown:.40}"),
                status,
                &headers,
                &text,
            );
            assert!(
                !text.contains("k4needle") && !text.contains("Zm9vOmJhcg"),
                "{route}: the header echoed: {text}"
            );
            assert!(!text.contains(&good[..20]), "{route}: the bearer echoed");
        }
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// The statuses that stay: a bad signature or an expired token is 401 (with
/// the challenge), another compute's token and a token without `compute_id`
/// or scope are 403, an admin token without the audience is 401.
#[tokio::test]
async fn the_other_answers_stay() {
    let dir = fresh("k4_auth_others");
    let key = new_key(Some("k4"));
    let stranger = new_key(Some("k4"));
    let router = external(&dir, &key);
    let exp = now() + 3600;
    let cases = [
        (
            "signed by another key",
            jwt(&stranger, json!({ "compute_id": COMPUTE_ID, "exp": exp })),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "expired 200 s ago",
            jwt(
                &key,
                json!({ "compute_id": COMPUTE_ID, "exp": now() - 200 }),
            ),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "admin without aud",
            jwt(&key, json!({ "scope": "compute_ctl:admin", "exp": exp })),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "another compute",
            jwt(&key, json!({ "compute_id": OTHER_ID, "exp": exp })),
            StatusCode::FORBIDDEN,
        ),
        ("no claims", jwt(&key, json!({})), StatusCode::FORBIDDEN),
    ];
    for (what, token, want) in cases {
        let auth = format!("Bearer {token}");
        let (status, headers, text) =
            call(&router, request(&Method::GET, "/status", Some(&auth))).await;
        if want == StatusCode::UNAUTHORIZED {
            assert_challenged(what, status, &headers, &text);
        } else {
            assert_eq!(status, want, "{what}: {text}");
        }
    }
    let ok = format!(
        "Bearer {}",
        jwt(&key, json!({ "compute_id": COMPUTE_ID, "exp": exp }))
    );
    let (status, _, text) = call(&router, request(&Method::GET, "/status", Some(&ok))).await;
    assert_eq!(status, StatusCode::OK, "this compute's token: {text}");
    fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// No INSTANCE_ID bypass (spec §5, S6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_instance_id_is_no_bypass() {
    let dir = fresh("k4_auth_instance_id");
    let key = new_key(Some("k4"));
    let router = external_with(
        &dir,
        JwkSet {
            keys: vec![key.jwk.clone()],
        },
        Some("hadron-instance-1"),
    );
    for route in [
        "/status",
        "/metrics",
        "/autoscaling_metrics",
        "/dbs_and_roles",
    ] {
        let (status, headers, text) = call(&router, request(&Method::GET, route, None)).await;
        assert_challenged(
            &format!("{route} without a token, INSTANCE_ID set"),
            status,
            &headers,
            &text,
        );
    }
    let other = format!(
        "Bearer {}",
        jwt(&key, json!({ "compute_id": OTHER_ID, "exp": now() + 3600 }))
    );
    let (status, _, text) = call(&router, request(&Method::GET, "/status", Some(&other))).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "another compute's token, INSTANCE_ID set: {text}"
    );
    let metrics = format!("Bearer {}", jwt(&key, json!({ "scope": "metrics" })));
    let (status, _, text) = call(&router, request(&Method::GET, "/status", Some(&metrics))).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a metrics token on /status, INSTANCE_ID set: {text}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// No bearer logged; no panic on a JWK without `kid` (spec §5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_bearer_reaches_the_log() {
    let dir = fresh("k4_auth_logs");
    let key = new_key(Some("k4"));
    let stranger = new_key(Some("k4"));
    let router = external(&dir, &key);
    let good = jwt(
        &key,
        json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 }),
    );
    let foreign = jwt(
        &stranger,
        json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 }),
    );
    let metrics = jwt(&key, json!({ "scope": "metrics" }));
    let (logs, guard) = Logs::capture();
    for route in ["/status", "/metrics"] {
        for token in [&good, &foreign, &metrics] {
            let auth = format!("Bearer {token}");
            call(&router, request(&Method::GET, route, Some(&auth))).await;
        }
        call(
            &router,
            request(&Method::GET, route, Some("Bearer k4needle.x.y")),
        )
        .await;
    }
    drop(guard);
    let text = logs.text();
    assert!(!text.is_empty(), "the capture saw the request logs");
    for (what, token) in [
        ("this compute's token", &good),
        ("a foreign token", &foreign),
        ("a metrics token", &metrics),
    ] {
        // A token's signature part is unique to it.
        let signature = token.rsplit('.').next().unwrap();
        assert!(!text.contains(signature), "{what} reached the log:\n{text}");
    }
    assert!(
        !text.contains("k4needle"),
        "a presented bearer reached the log:\n{text}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

/// Runs one request on its own task: a panic in the middleware shows up as a
/// panicked `JoinError` instead of tearing the test down.
async fn call_catching(router: &Router, req: Request<Body>) -> Result<StatusCode, String> {
    let router = router.clone();
    match tokio::spawn(async move { router.oneshot(req).await }).await {
        Ok(res) => Ok(res.unwrap().status()),
        Err(e) if e.is_panic() => Err(format!("{e:?}")),
        Err(e) => panic!("the request task failed: {e}"),
    }
}

#[tokio::test]
async fn a_jwk_without_kid_is_skipped_not_a_panic() {
    let signer = new_key(Some("k4-right"));
    let wrong_no_kid = new_key(None);
    let right_no_kid = Key {
        encoding: signer.encoding.clone(),
        jwk: Jwk {
            common: common(None),
            ..signer.jwk.clone()
        },
    };
    let token = format!(
        "Bearer {}",
        jwt(
            &signer,
            json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 })
        )
    );
    let cases = [
        (
            "a wrong key without kid, then the right one",
            vec![wrong_no_kid.jwk.clone(), signer.jwk.clone()],
            StatusCode::OK,
        ),
        (
            "a key that can't be built, without kid, then the right one",
            vec![broken_jwk(None), signer.jwk.clone()],
            StatusCode::OK,
        ),
        (
            "only a wrong key without kid",
            vec![wrong_no_kid.jwk.clone()],
            StatusCode::UNAUTHORIZED,
        ),
        (
            "the right key without kid",
            vec![right_no_kid.jwk.clone()],
            StatusCode::OK,
        ),
    ];
    // `tracing` only evaluates a log line's arguments when a subscriber takes
    // it (compute_ctl always runs with one): capture at TRACE, so a `kid`
    // unwrapped while logging runs here as in production.
    let (_logs, _guard) = Logs::capture();
    for (i, (what, keys, want)) in cases.into_iter().enumerate() {
        let dir = fresh(&format!("k4_auth_kid_{i}"));
        let router = external_with(&dir, JwkSet { keys }, None);
        let status = call_catching(&router, request(&Method::GET, "/status", Some(&token)))
            .await
            .unwrap_or_else(|panic| panic!("{what}: the middleware panicked: {panic}"));
        assert_eq!(status, want, "{what}");
        fs::remove_dir_all(&dir).unwrap();
    }
}

// ---------------------------------------------------------------------------
// The metrics routes (U4, S18) and the `metrics` scope (RT4-9)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_metrics_routes_need_a_token() {
    let dir = fresh("k4_auth_metrics_open");
    let key = new_key(Some("k4"));
    let router = external(&dir, &key);
    for route in METRICS_ROUTES {
        let (status, headers, text) = call(&router, request(&Method::GET, route, None)).await;
        assert_challenged(&format!("{route} without a token"), status, &headers, &text);
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// A guard (passes before K4 too, since the routes are open today): what the
/// metrics routes keep accepting once they need a token.
#[tokio::test]
async fn the_metrics_routes_take_metrics_admin_and_this_computes_tokens() {
    let dir = fresh("k4_auth_metrics_tokens");
    let key = new_key(Some("k4"));
    let router = external(&dir, &key);
    let exp = now() + 3600;
    let accepted = [
        ("metrics, no compute_id", json!({ "scope": "metrics" })),
        (
            "metrics, no compute_id, iat (Chelabase's form)",
            json!({ "scope": "metrics", "iat": now() }),
        ),
        (
            "metrics, this compute_id",
            json!({ "scope": "metrics", "compute_id": COMPUTE_ID }),
        ),
        (
            "metrics, another compute_id",
            json!({ "scope": "metrics", "compute_id": OTHER_ID }),
        ),
        (
            "metrics, with aud and a future exp",
            json!({ "scope": "metrics", "aud": ["compute"], "exp": exp }),
        ),
        (
            "compute_ctl:admin",
            json!({ "scope": "compute_ctl:admin", "aud": ["compute"], "exp": exp }),
        ),
        (
            "this compute's control token",
            json!({ "compute_id": COMPUTE_ID, "exp": exp }),
        ),
    ];
    for (what, claims) in accepted {
        let auth = format!("Bearer {}", jwt(&key, claims));
        let (status, _, text) = call(&router, request(&Method::GET, "/metrics", Some(&auth))).await;
        assert_eq!(status, StatusCode::OK, "/metrics with {what}: {text}");
        let (status, _, text) = call(
            &router,
            request(&Method::GET, "/autoscaling_metrics", Some(&auth)),
        )
        .await;
        assert_reached(&format!("/autoscaling_metrics with {what}"), status, &text);
        let (status, _, text) = call(
            &router,
            request(&Method::GET, "/metrics?name=x", Some(&auth)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "/metrics?name=x with {what}: {text}"
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_metrics_routes_refuse_foreign_and_expired_tokens() {
    let dir = fresh("k4_auth_metrics_refused");
    let key = new_key(Some("k4"));
    let router = external(&dir, &key);
    let exp = now() + 3600;
    let refused = [
        (
            "another compute's control token",
            json!({ "compute_id": OTHER_ID, "exp": exp }),
            StatusCode::FORBIDDEN,
        ),
        ("no claims", json!({}), StatusCode::FORBIDDEN),
        (
            "metrics, expired 120 s ago",
            json!({ "scope": "metrics", "exp": now() - 120 }),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "metrics, expired 200 s ago",
            json!({ "scope": "metrics", "exp": now() - 200 }),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "admin, expired 200 s ago",
            json!({ "scope": "compute_ctl:admin", "aud": ["compute"], "exp": now() - 200 }),
            StatusCode::UNAUTHORIZED,
        ),
    ];
    for route in METRICS_ROUTES {
        for (what, claims, want) in &refused {
            let auth = format!("Bearer {}", jwt(&key, claims.clone()));
            let (status, headers, text) =
                call(&router, request(&Method::GET, route, Some(&auth))).await;
            if *want == StatusCode::UNAUTHORIZED {
                assert_challenged(&format!("{route} with {what}"), status, &headers, &text);
            } else {
                assert_eq!(status, *want, "{route} with {what}: {text}");
            }
        }
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// RT4-9: a `metrics` token opens nothing but the two metrics routes, whatever
/// `compute_id` it carries (this compute's included) and with or without
/// `aud`; the decision is by path, so neither a longer route that starts with
/// `/metrics` nor `/metrics` in the query string opens anything.
#[tokio::test]
async fn a_metrics_token_opens_no_other_route() {
    let dir = fresh("k4_auth_metrics_elsewhere");
    let key = new_key(Some("k4"));
    let router = external(&dir, &key);
    let exp = now() + 3600;
    let tokens = [
        ("no compute_id", json!({ "scope": "metrics" })),
        (
            "this compute_id",
            json!({ "scope": "metrics", "compute_id": COMPUTE_ID, "exp": exp }),
        ),
        (
            "another compute_id",
            json!({ "scope": "metrics", "compute_id": OTHER_ID }),
        ),
        (
            "this compute_id and aud",
            json!({ "scope": "metrics", "compute_id": COMPUTE_ID, "aud": ["compute"] }),
        ),
    ];
    let mut routes: Vec<(Method, String)> = OTHER_ROUTES
        .iter()
        .map(|(m, r)| (method(m), (*r).to_owned()))
        .collect();
    routes.push((Method::GET, "/status?/metrics".into()));
    routes.push((Method::GET, "/status?x=/autoscaling_metrics".into()));
    for (what, claims) in &tokens {
        let auth = format!("Bearer {}", jwt(&key, claims.clone()));
        for (m, route) in &routes {
            let (status, _, text) = call(&router, request(m, route, Some(&auth))).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{m} {route} with a metrics token ({what}): {text}"
            );
        }
        // Not a route at all, or another method: never a success.
        for (m, route) in [
            (Method::POST, "/metrics"),
            (Method::POST, "/autoscaling_metrics"),
            (Method::GET, "/metrics/"),
            (Method::GET, "/metrics/x"),
            (Method::GET, "/autoscaling_metrics/x"),
        ] {
            let (status, _, text) = call(&router, request(&m, route, Some(&auth))).await;
            assert!(
                !status.is_success(),
                "{m} {route} with a metrics token ({what}): {status} {text}"
            );
        }
    }
    fs::remove_dir_all(&dir).unwrap();
}
