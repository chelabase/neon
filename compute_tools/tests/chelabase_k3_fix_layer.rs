//! Fork round 4, K3 fix round: the internal router fails closed by
//! construction. The `InternalAuth` extractor stays on every internal handler;
//! the served internal router also carries a route layer doing the same bearer
//! check, so a route added later without the extractor is still refused.
//!
//! Pinned interface (the code under test):
//! - `Server::with_internal_auth(router: Router<Arc<ComputeNode>>, compute:
//!   &Arc<ComputeNode>) -> Router<Arc<ComputeNode>>`: `router.route_layer(
//!   middleware::from_fn_with_state(Arc::clone(compute), …))` with the same check
//!   and the same `401` (`WWW-Authenticate: Bearer`, a body never echoing the
//!   header) as `InternalAuth`. `Server::serve` applies it to the internal
//!   router (`Router::from(&Server::Internal { port })`, which has no compute)
//!   before `with_state`; the external router doesn't get it.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use compute_api::responses::{ComputeConfig, ComputeCtlConfig, ComputeStatus};
use compute_tools::compute::{ComputeNode, ComputeNodeParams};
use compute_tools::http::server::Server;
use compute_tools::token_file::STORAGE_AUTH_TOKEN_FILE;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");
/// What the unguarded test route answers when it runs.
const SERVED: &str = "k3fix-unguarded-handler-ran";

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn compute(dir: &Path) -> Arc<ComputeNode> {
    let params = ComputeNodeParams {
        compute_id: "compute-test".into(),
        connstr: url::Url::parse("postgresql://cloud_admin@127.0.0.1:1/postgres").unwrap(),
        privileged_role_name: "neon_superuser".into(),
        resize_swap_on_bind: false,
        set_disk_quota_for_fs: None,
        pgdata: dir.join("pgdata").to_string_lossy().into(),
        pgbin: "/nonexistent".into(),
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
        internal_api_token_file: dir.join("compute_ctl_internal.token"),
        storage_auth_token_file: dir.join(STORAGE_AUTH_TOKEN_FILE),
    };
    let mut spec: Value = serde_json::from_str(SPEC).unwrap();
    spec["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
    let obj = spec.as_object_mut().unwrap();
    obj.remove("pgbouncer_settings");
    obj.remove("storage_auth_token");
    let compute = ComputeNode::new(
        params,
        ComputeConfig {
            spec: Some(serde_json::from_value(spec).unwrap()),
            compute_ctl_config: ComputeCtlConfig::default(),
        },
    )
    .unwrap();
    compute.set_status(ComputeStatus::Empty);
    Arc::new(compute)
}

/// The internal router as `serve` serves it, plus a route whose handler takes
/// no `InternalAuth` (a route someone adds later and forgets the extractor on).
fn served_with_unguarded_route(compute: &Arc<ComputeNode>) -> Router {
    let router = Router::from(&Server::Internal { port: 3081 })
        .route("/k3fix/unguarded", get(|| async { SERVED }));
    Server::with_internal_auth(router, compute).with_state(Arc::clone(compute))
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

fn get_unguarded(auth: &[&str]) -> Request<Body> {
    let mut req = Request::builder().method("GET").uri("/k3fix/unguarded");
    for value in auth {
        req = req.header("authorization", *value);
    }
    req.body(Body::empty()).unwrap()
}

/// A route without the extractor is refused without the exact bearer, with the
/// same `401` as the extractor's, and served with it.
#[tokio::test]
async fn a_route_without_the_extractor_still_needs_the_bearer() {
    let dir = fresh("k3fix_layer_unguarded");
    let compute = compute(&dir);
    let router = served_with_unguarded_route(&compute);
    let secret = compute.internal_api_secret().to_owned();
    let bearer = format!("Bearer {secret}");
    let wrong = format!("Bearer {}", "0".repeat(secret.len()));

    for (case, auth) in [
        ("no header", vec![]),
        ("a wrong secret", vec![wrong.as_str()]),
        ("a Basic scheme", vec!["Basic dXNlcjpwYXNz"]),
        ("the secret without a scheme", vec![secret.as_str()]),
        ("two headers", vec![bearer.as_str(), bearer.as_str()]),
    ] {
        let (status, headers, body) = call(&router, get_unguarded(&auth)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}: {body}");
        assert_eq!(
            headers
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer"),
            "{case}"
        );
        assert!(!body.contains(SERVED), "{case}: the handler ran");
        assert!(!body.contains(&secret), "{case}: the secret in the body");
        assert!(!body.contains("dXNlcjpwYXNz"), "{case}: a header echoed");
    }

    let (status, _, body) = call(&router, get_unguarded(&[&bearer])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, SERVED);
    fs::remove_dir_all(&dir).unwrap();
}

/// The layer and the extractor agree: an existing route with the bearer gets
/// past both to its handler (any answer but `401`), and without it is `401`.
#[tokio::test]
async fn existing_routes_pass_the_layer_with_the_bearer() {
    let dir = fresh("k3fix_layer_existing");
    let compute = compute(&dir);
    let router = served_with_unguarded_route(&compute);
    let bearer = format!("Bearer {}", compute.internal_api_secret());
    let grants = |auth: Option<&str>| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/grants")
            .header("content-type", "application/json");
        if let Some(auth) = auth {
            req = req.header("authorization", auth);
        }
        req.body(Body::from("{}")).unwrap()
    };

    let (status, _, body) = call(&router, grants(None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, _, body) = call(&router, grants(Some(&bearer))).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{body}");
    fs::remove_dir_all(&dir).unwrap();
}
