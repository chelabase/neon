//! Fork round 4, K3: compute_ctl's HTTP side of D2, item 7 and the red-team
//! rulings (spec §4, §8; RT4-2, RT4-3, RT4-6, RT4-7, RT4-10; plan P4, P5, SP5,
//! SP6, SP7). Every test drives the real routers with `oneshot`.
//!
//! Pinned interfaces (the code under test):
//! - `ComputeNodeParams.internal_api_token_file: PathBuf` and
//!   `ComputeNodeParams.storage_auth_token_file: PathBuf` (from
//!   `--internal-api-token-file`, `--storage-auth-token-file`; defaults
//!   `token_file::default_token_path(pgdata, …)`).
//! - `ComputeNode::internal_api_secret(&self) -> &str`: the per-start secret,
//!   drawn in `ComputeNode::new` (`token_file::generate_internal_api_secret`).
//! - `Server::Internal { port }` (unchanged) gets its secret from the
//!   `ComputeNode` state: every internal route needs `Authorization: Bearer
//!   <secret>` (constant-time compare; no `INSTANCE_ID` bypass); anything else is
//!   `401` + `WWW-Authenticate: Bearer` + `{"error": …}` never echoing the header.
//! - `Server::listen_addrs(&self) -> Vec<SocketAddr>`: internal
//!   `[127.0.0.1:<port>, [::1]:<port>]` (`::1` best effort when binding), external
//!   `[[::]:<port>]` (unchanged).
//! - `ParsedSpec.storage_auth_token: Option<StorageAuthToken>` (`as_str()`).
//! - `ComputeStatusResponse.capabilities` = `["storage_token_refresh"]` when the
//!   compute holds a storage token, `[]` otherwise (SP6, final fix round).
//! - `POST /storage_token` on the external router, body `{"token": …}`, this
//!   compute's control token or an admin token: `204` (file written, then the
//!   token in `state.pspec` and `pspec.spec` replaced; status unchanged) in
//!   `running` and `configuration_pending`; `412` in every other status (nothing
//!   written); `400` for any body rejection, a token outside the alphabet or
//!   size, or a compute that started without a storage token ("restart"); `500`
//!   when the file can't be written (old file and in-memory token kept). No error
//!   text contains the token.
//! - `/configure` on a compute holding a storage token with a spec whose token is
//!   absent or empty, and on a compute without one with a spec that adds one:
//!   `400` before anything changes (RT4-7, SP6).
//! - `/grants` (RT4-6): only `USAGE`/`CREATE`; never `pg_catalog`,
//!   `information_schema`, `pg_toast*`; never to `cloud_admin`, the privileged role
//!   (`neon_superuser`), a `pg_*` role, `cb_m_*` (any case) or
//!   `chelabase_realtime`. Those name rules are decided before any connection
//!   (`403`); the catalog rules (superuser-owned schema, superuser or marked or
//!   missing grantee) are in `test_compute_http.py`.

use std::ffi::OsString;
use std::fs;
use std::net::SocketAddr;
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
use compute_api::responses::{
    ComputeConfig, ComputeCtlConfig, ComputeStatus, ComputeStatusResponse,
};
use compute_tools::compute::{ComputeNode, ComputeNodeParams, ComputeState};
use compute_tools::http::server::Server;
use compute_tools::token_file::{INTERNAL_API_TOKEN_FILE, STORAGE_AUTH_TOKEN_FILE};
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

const COMPUTE_ID: &str = "compute-test";
const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");
/// The token a compute started with, and a refreshed one (both valid tokens).
const OLD: &str = "k3old.eyJ0ZW5hbnQiOjF9.c2lnLW9sZA";
const NEW: &str = "k3new.eyJ0ZW5hbnQiOjJ9.c2lnLW5ldw";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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

fn spec_json(token: Option<&str>) -> Value {
    let mut json: Value = serde_json::from_str(SPEC).unwrap();
    json["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
    match token {
        Some(token) => json["storage_auth_token"] = json!(token),
        None => {
            json.as_object_mut().unwrap().remove("storage_auth_token");
        }
    }
    json
}

struct Keys {
    encoding: EncodingKey,
    jwks: JwkSet,
}

fn keys() -> Keys {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: None,
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            key_id: Some("k3-test".into()),
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        },
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: BASE64_URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
        }),
    };
    Keys {
        encoding: EncodingKey::from_ed_der(pkcs8.as_ref()),
        jwks: JwkSet { keys: vec![jwk] },
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn jwt(keys: &Keys, claims: Value) -> String {
    jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &keys.encoding).unwrap()
}

/// This compute's control token, as Chelabase mints it (`{compute_id, exp}`).
fn control_token(keys: &Keys) -> String {
    jwt(
        keys,
        json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 }),
    )
}

fn admin_token(keys: &Keys) -> String {
    jwt(
        keys,
        json!({ "scope": "compute_ctl:admin", "aud": ["compute"], "exp": now() + 3600 }),
    )
}

fn compute_with(
    params: ComputeNodeParams,
    keys: &Keys,
    token: Option<&str>,
    status: ComputeStatus,
) -> Arc<ComputeNode> {
    let spec = serde_json::from_value(spec_json(token)).unwrap();
    let compute = ComputeNode::new(
        params,
        ComputeConfig {
            spec: Some(spec),
            compute_ctl_config: ComputeCtlConfig {
                jwks: keys.jwks.clone(),
                tls: None,
            },
        },
    )
    .unwrap();
    compute.set_status(status);
    Arc::new(compute)
}

fn make_compute(
    dir: &Path,
    keys: &Keys,
    token: Option<&str>,
    status: ComputeStatus,
) -> Arc<ComputeNode> {
    compute_with(params(dir), keys, token, status)
}

fn external(compute: &Arc<ComputeNode>, keys: &Keys) -> Router {
    Router::from(&Server::External {
        port: 3080,
        config: ComputeCtlConfig {
            jwks: keys.jwks.clone(),
            tls: None,
        },
        compute_id: COMPUTE_ID.into(),
        instance_id: compute.params.instance_id.clone(),
    })
    .with_state(Arc::clone(compute))
}

fn internal(compute: &Arc<ComputeNode>) -> Router {
    Router::from(&Server::Internal { port: 3081 }).with_state(Arc::clone(compute))
}

fn post(uri: &str, auth: Option<&str>, body: Option<&str>) -> Request<Body> {
    let mut req = Request::builder().method("POST").uri(uri);
    if let Some(auth) = auth {
        req = req.header("authorization", auth);
    }
    match body {
        Some(body) => req
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
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

fn storage_token_body(token: &str) -> String {
    json!({ "token": token }).to_string()
}

fn file(dir: &Path) -> Option<String> {
    fs::read_to_string(dir.join(STORAGE_AUTH_TOKEN_FILE)).ok()
}

/// The token compute_ctl holds in memory: `(pspec.storage_auth_token,
/// pspec.spec.storage_auth_token)`.
fn held(compute: &ComputeNode) -> (Option<String>, Option<String>) {
    let state = compute.state.lock().unwrap();
    let pspec = state.pspec.as_ref().unwrap();
    (
        pspec
            .storage_auth_token
            .as_ref()
            .map(|t| t.as_str().to_owned()),
        pspec
            .spec
            .storage_auth_token
            .as_ref()
            .map(|t| t.as_str().to_owned()),
    )
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
// The internal server (D2, RT4-10, P5)
// ---------------------------------------------------------------------------

/// Each internal route with a body its handler accepts.
fn internal_routes() -> Vec<(&'static str, Option<&'static str>)> {
    let mut routes = vec![
        (
            "/extensions",
            Some(r#"{"extension":"neon_test_utils","database":"postgres","version":"1.3"}"#),
        ),
        (
            "/grants",
            Some(
                r#"{"database":"postgres","schema":"app","privileges":["USAGE"],"role":"app_user"}"#,
            ),
        ),
        ("/extension_server/anon.tar.zst", None),
        ("/refresh_configuration", None),
    ];
    if cfg!(feature = "testing") {
        routes.push(("/failpoints", Some("[]")));
    }
    routes
}

fn assert_refused(
    route: &str,
    presented: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &str,
) {
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{route} with {presented:?}: {body}"
    );
    let challenge = headers
        .get("www-authenticate")
        .unwrap_or_else(|| panic!("{route} with {presented:?}: no WWW-Authenticate"))
        .to_str()
        .unwrap();
    assert!(challenge.starts_with("Bearer"), "{route}: {challenge}");
    let json: Value = serde_json::from_str(body)
        .unwrap_or_else(|_| panic!("{route} with {presented:?}: not JSON: {body}"));
    assert!(json["error"].is_string(), "{route}: {body}");
}

#[tokio::test]
async fn every_internal_route_needs_the_secret() {
    let dir = fresh("k3_http_internal_refused");
    let keys = keys();
    let compute = make_compute(&dir, &keys, None, ComputeStatus::Empty);
    let other = make_compute(
        &fresh("k3_http_internal_other"),
        &keys,
        None,
        ComputeStatus::Empty,
    );
    let secret = compute.internal_api_secret().to_owned();
    let router = internal(&compute);

    let presented: Vec<Option<String>> = vec![
        None,
        Some("Basic Zm9vOmJhcg==".into()),
        Some("Bearer".into()),
        Some("Bearer ".into()),
        Some("Bearer wrong-k3needle".into()),
        Some(format!("Bearer {secret}x")),
        Some(format!("Bearer x{secret}")),
        Some(format!("Bearer {}", &secret[..63])),
        Some(format!("Bearer {}", secret.to_uppercase())),
        Some(format!("Bearer {secret} {secret}")),
        Some(format!("Token {secret}")),
        Some(secret.clone()),
        Some(format!("Bearer {}", other.internal_api_secret())),
    ];
    for (route, body) in internal_routes() {
        for auth in &presented {
            let (status, headers, text) = call(&router, post(route, auth.as_deref(), body)).await;
            let shown = auth.as_deref().unwrap_or("<none>");
            assert_refused(route, shown, status, &headers, &text);
            assert!(
                !text.contains(&secret[..16]),
                "{route}: the secret echoed: {text}"
            );
            assert!(
                !text.contains("k3needle") && !text.contains("Zm9vOmJhcg"),
                "{route}: {text}"
            );
        }
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_right_secret_runs_the_route() {
    let dir = fresh("k3_http_internal_served");
    let keys = keys();
    let compute = make_compute(&dir, &keys, None, ComputeStatus::Empty);
    let auth = format!("Bearer {}", compute.internal_api_secret());
    let router = internal(&compute);

    // Each handler's own answer for an `empty` compute without remote storage.
    let expected = [
        ("/extensions", StatusCode::PRECONDITION_FAILED),
        ("/grants", StatusCode::PRECONDITION_FAILED),
        (
            "/extension_server/anon.tar.zst",
            StatusCode::PRECONDITION_FAILED,
        ),
        ("/refresh_configuration", StatusCode::INTERNAL_SERVER_ERROR),
        ("/failpoints", StatusCode::OK),
    ];
    for (route, body) in internal_routes() {
        let want = expected.iter().find(|(r, _)| *r == route).unwrap().1;
        let (status, _, text) = call(&router, post(route, Some(&auth), body)).await;
        assert_eq!(status, want, "{route}: {text}");
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn an_instance_id_is_no_bypass() {
    let dir = fresh("k3_http_internal_instance_id");
    let keys = keys();
    let mut params = params(&dir);
    params.instance_id = Some("hadron-instance-1".into());
    let compute = compute_with(params, &keys, None, ComputeStatus::Empty);
    let router = internal(&compute);
    for (route, body) in internal_routes() {
        let (status, headers, text) = call(&router, post(route, None, body)).await;
        assert_refused(route, "<none, INSTANCE_ID set>", status, &headers, &text);
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_secret_is_per_start_and_never_logged() {
    let dir = fresh("k3_http_internal_logs");
    let keys = keys();
    let compute = make_compute(&dir, &keys, None, ComputeStatus::Empty);
    let again = compute_with(params(&dir), &keys, None, ComputeStatus::Empty);
    let secret = compute.internal_api_secret().to_owned();
    assert_eq!(secret.len(), 64, "{secret}");
    assert!(
        secret
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert_ne!(
        secret,
        again.internal_api_secret(),
        "a new secret per start"
    );

    let router = internal(&compute);
    let (logs, guard) = Logs::capture();
    for (route, body) in internal_routes() {
        for auth in [
            None,
            Some(format!("Bearer {secret}")),
            Some(format!("Bearer {secret}x")),
            Some("Bearer wrong-k3needle".to_string()),
        ] {
            call(&router, post(route, auth.as_deref(), body)).await;
        }
    }
    drop(guard);
    let text = logs.text();
    assert!(!text.is_empty(), "the capture saw the request logs");
    assert!(
        !text.contains(&secret[..16]),
        "the secret reached the log:\n{text}"
    );
    assert!(
        !text.contains("k3needle"),
        "a presented bearer reached the log:\n{text}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_internal_server_listens_on_loopback_only() {
    let internal: Vec<SocketAddr> = Server::Internal { port: 3081 }.listen_addrs();
    assert_eq!(
        internal,
        vec![
            "127.0.0.1:3081".parse::<SocketAddr>().unwrap(),
            "[::1]:3081".parse::<SocketAddr>().unwrap(),
        ]
    );
    let external = Server::External {
        port: 3080,
        config: ComputeCtlConfig::default(),
        compute_id: COMPUTE_ID.into(),
        instance_id: None,
    }
    .listen_addrs();
    assert_eq!(external, vec!["[::]:3080".parse::<SocketAddr>().unwrap()]);
}

// ---------------------------------------------------------------------------
// The capability (RT4-2)
// ---------------------------------------------------------------------------

/// SP6 (final fix round): `/status` advertises `storage_token_refresh` only when
/// the compute holds a storage token. One started without (or with no spec yet)
/// answers `POST /storage_token` with 400, so advertising the capability would
/// make the control plane hand it expiring tokens it can never refresh.
#[tokio::test]
async fn status_advertises_the_storage_token_refresh() {
    let from_state = ComputeStatusResponse::from(&ComputeState::new());
    assert_eq!(
        from_state.capabilities,
        Vec::<String>::new(),
        "no spec yet: no storage token to refresh"
    );

    let keys = keys();
    for (name, token, want) in [
        (
            "k3_http_status",
            Some(OLD),
            json!(["storage_token_refresh"]),
        ),
        ("f1_http_status_no_token", None, json!([])),
    ] {
        let dir = fresh(name);
        let compute = make_compute(&dir, &keys, token, ComputeStatus::Running);
        let req = Request::builder()
            .method("GET")
            .uri("/status")
            .header("authorization", format!("Bearer {}", control_token(&keys)))
            .body(Body::empty())
            .unwrap();
        let (status, _, text) = call(&external(&compute, &keys), req).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let json: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["capabilities"], want, "token {token:?}: {text}");
        assert!(!text.contains("k3old"), "/status shows no token: {text}");
        fs::remove_dir_all(&dir).unwrap();
    }
}

// ---------------------------------------------------------------------------
// POST /storage_token (RT4-3, SP5, SP6, SP7)
// ---------------------------------------------------------------------------

fn refresh(keys: &Keys, body: &str) -> Request<Body> {
    post(
        "/storage_token",
        Some(&format!("Bearer {}", control_token(keys))),
        Some(body),
    )
}

#[tokio::test]
async fn a_refresh_writes_the_file_and_the_held_token() {
    let dir = fresh("k3_http_refresh_ok");
    let keys = keys();
    let compute = make_compute(&dir, &keys, Some(OLD), ComputeStatus::Running);
    fs::write(dir.join(STORAGE_AUTH_TOKEN_FILE), format!("{OLD}\n")).unwrap();
    let router = external(&compute, &keys);

    let (status, _, text) = call(&router, refresh(&keys, &storage_token_body(NEW))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    assert_eq!(file(&dir).as_deref(), Some(format!("{NEW}\n").as_str()));
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(dir.join(STORAGE_AUTH_TOKEN_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode, 0o600);
    // SP5: compute_ctl's own pageserver calls and the LSN-lease loop read the
    // held token, so it follows the file.
    assert_eq!(held(&compute), (Some(NEW.into()), Some(NEW.into())));
    assert_eq!(
        compute.get_status(),
        ComputeStatus::Running,
        "no status change"
    );

    // An admin token is accepted too.
    let admin = post(
        "/storage_token",
        Some(&format!("Bearer {}", admin_token(&keys))),
        Some(&storage_token_body(OLD)),
    );
    let (status, _, text) = call(&router, admin).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    assert_eq!(file(&dir).as_deref(), Some(format!("{OLD}\n").as_str()));
    assert_eq!(held(&compute), (Some(OLD.into()), Some(OLD.into())));
    fs::remove_dir_all(&dir).unwrap();
}

fn refresh_allowed(status: ComputeStatus) -> bool {
    match status {
        ComputeStatus::Running | ComputeStatus::ConfigurationPending => true,
        ComputeStatus::Empty
        | ComputeStatus::Init
        | ComputeStatus::Configuration
        | ComputeStatus::Failed
        | ComputeStatus::TerminationPendingFast
        | ComputeStatus::TerminationPendingImmediate
        | ComputeStatus::Terminated
        | ComputeStatus::RefreshConfigurationPending
        | ComputeStatus::RefreshConfiguration => false,
    }
}

/// Every status: a refresh works in `running` and `configuration_pending` (it
/// never waits behind a reconfigure), answers `412` and writes nothing in any
/// other, and never changes the status.
#[tokio::test]
async fn a_refresh_works_only_while_running_or_pending() {
    let keys = keys();
    let all = [
        ComputeStatus::Empty,
        ComputeStatus::ConfigurationPending,
        ComputeStatus::Init,
        ComputeStatus::Running,
        ComputeStatus::Configuration,
        ComputeStatus::Failed,
        ComputeStatus::TerminationPendingFast,
        ComputeStatus::TerminationPendingImmediate,
        ComputeStatus::Terminated,
        ComputeStatus::RefreshConfigurationPending,
        ComputeStatus::RefreshConfiguration,
    ];
    for status in all {
        let dir = fresh(&format!("k3_http_refresh_status_{status}"));
        let compute = make_compute(&dir, &keys, Some(OLD), status);
        fs::write(dir.join(STORAGE_AUTH_TOKEN_FILE), format!("{OLD}\n")).unwrap();
        let (code, _, text) = call(
            &external(&compute, &keys),
            refresh(&keys, &storage_token_body(NEW)),
        )
        .await;
        if refresh_allowed(status) {
            assert_eq!(code, StatusCode::NO_CONTENT, "{status}: {text}");
            assert_eq!(
                file(&dir).as_deref(),
                Some(format!("{NEW}\n").as_str()),
                "{status}"
            );
            assert_eq!(
                held(&compute),
                (Some(NEW.into()), Some(NEW.into())),
                "{status}"
            );
        } else {
            assert_eq!(code, StatusCode::PRECONDITION_FAILED, "{status}: {text}");
            assert_eq!(
                file(&dir).as_deref(),
                Some(format!("{OLD}\n").as_str()),
                "{status}"
            );
            assert_eq!(
                held(&compute),
                (Some(OLD.into()), Some(OLD.into())),
                "{status}"
            );
            assert!(!text.contains("k3new"), "{status}: {text}");
        }
        assert_eq!(
            compute.get_status(),
            status,
            "{status}: the status is unchanged"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}

#[tokio::test]
async fn a_refresh_refuses_anything_but_one_valid_token() {
    let dir = fresh("k3_http_refresh_bad");
    let keys = keys();
    let compute = make_compute(&dir, &keys, Some(OLD), ComputeStatus::Running);
    fs::write(dir.join(STORAGE_AUTH_TOKEN_FILE), format!("{OLD}\n")).unwrap();
    let router = external(&compute, &keys);
    let control = format!("Bearer {}", control_token(&keys));

    let long = "k".repeat(8192);
    let bad_tokens = [
        "",
        "k3bad secret",
        "k3bad\nsecret",
        "k3bad\nk3bad",
        "k3bad;secret",
        "k3bad'secret",
        "k3bad\"secret",
        "k3bad\\secret",
        "k3bad\u{e9}secret",
        "k3bad\0secret",
        long.as_str(),
    ];
    for token in bad_tokens {
        let (status, _, text) = call(&router, refresh(&keys, &storage_token_body(token))).await;
        let shown = &token[..token.len().min(16)];
        assert_eq!(status, StatusCode::BAD_REQUEST, "{shown:?}: {text}");
        assert!(
            !text.contains("k3bad") && !text.contains(&long[..64]),
            "token echoed: {text}"
        );
    }
    // Every body rejection is a 400, never axum's 415 or 422 (SP7).
    let rejections: [(Option<&str>, &str); 7] = [
        (Some("application/json"), "not json"),
        (Some("application/json"), "{}"),
        (Some("application/json"), r#"{"token": 5}"#),
        (Some("application/json"), r#"{"token": null}"#),
        (Some("application/json"), r#"["k3new"]"#),
        (Some("text/plain"), r#"{"token": "k3new.a.b"}"#),
        (None, r#"{"token": "k3new.a.b"}"#),
    ];
    for (content_type, body) in rejections {
        let mut req = Request::builder()
            .method("POST")
            .uri("/storage_token")
            .header("authorization", &control);
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        let (status, _, text) = call(&router, req.body(Body::from(body)).unwrap()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{content_type:?} {body}: {text}"
        );
    }
    assert_eq!(
        file(&dir).as_deref(),
        Some(format!("{OLD}\n").as_str()),
        "file kept"
    );
    assert_eq!(
        held(&compute),
        (Some(OLD.into()), Some(OLD.into())),
        "held token kept"
    );
    assert_eq!(compute.get_status(), ComputeStatus::Running);

    // The limits themselves are tokens.
    let max = "k".repeat(8191);
    let (status, _, text) = call(&router, refresh(&keys, &storage_token_body(&max))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "8191 bytes: {text}");
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/=-";
    let (status, _, text) = call(&router, refresh(&keys, &storage_token_body(alphabet))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the whole alphabet: {text}");
    assert_eq!(
        file(&dir).as_deref(),
        Some(format!("{alphabet}\n").as_str())
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_refresh_needs_this_computes_token() {
    let dir = fresh("k3_http_refresh_auth");
    let keys = keys();
    let compute = make_compute(&dir, &keys, Some(OLD), ComputeStatus::Running);
    fs::write(dir.join(STORAGE_AUTH_TOKEN_FILE), format!("{OLD}\n")).unwrap();
    let router = external(&compute, &keys);
    let body = storage_token_body(NEW);

    let other_keys = self::keys();
    let cases = [
        (
            "a bearer that isn't a JWT",
            Some("Bearer not-a-jwt".to_string()),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "another key's token",
            Some(format!("Bearer {}", control_token(&other_keys))),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "an expired control token",
            Some(format!(
                "Bearer {}",
                jwt(
                    &keys,
                    json!({ "compute_id": COMPUTE_ID, "exp": now() - 600 })
                )
            )),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "another compute's control token",
            Some(format!(
                "Bearer {}",
                jwt(
                    &keys,
                    json!({ "compute_id": "compute-other", "exp": now() + 3600 })
                )
            )),
            StatusCode::FORBIDDEN,
        ),
    ];
    for (what, auth, want) in cases {
        let (status, _, text) = call(
            &router,
            post("/storage_token", auth.as_deref(), Some(&body)),
        )
        .await;
        assert_eq!(status, want, "{what}: {text}");
    }
    let (status, _, _) = call(&router, post("/storage_token", None, Some(&body))).await;
    assert!(
        status.is_client_error() && status != StatusCode::NOT_FOUND,
        "no bearer: {status}"
    );
    assert_eq!(
        file(&dir).as_deref(),
        Some(format!("{OLD}\n").as_str()),
        "file kept"
    );
    assert_eq!(held(&compute), (Some(OLD.into()), Some(OLD.into())));
    fs::remove_dir_all(&dir).unwrap();
}

/// SP6: a compute that started without a storage token wrote `''` as the file
/// path (a `PGC_POSTMASTER` setting), so a token can't take effect before a
/// restart: refused, nothing written.
#[tokio::test]
async fn a_compute_started_without_a_token_refuses_one() {
    let dir = fresh("k3_http_refresh_no_auth");
    let keys = keys();
    let compute = make_compute(&dir, &keys, None, ComputeStatus::Running);
    let (status, _, text) = call(
        &external(&compute, &keys),
        refresh(&keys, &storage_token_body(NEW)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.to_lowercase().contains("restart"), "{text}");
    assert!(!text.contains("k3new"), "{text}");
    assert!(file(&dir).is_none(), "no file written");
    assert_eq!(held(&compute), (None, None));
    assert_eq!(compute.get_status(), ComputeStatus::Running);
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_failed_write_keeps_the_old_token() {
    let dir = fresh("k3_http_refresh_write_fails");
    let keys = keys();
    let mut params = params(&dir);
    // A directory where the file should be: the rename over it fails.
    let blocked = dir.join("blocked.token");
    fs::create_dir(&blocked).unwrap();
    params.storage_auth_token_file = blocked.clone();
    let compute = compute_with(params, &keys, Some(OLD), ComputeStatus::Running);
    let (status, _, text) = call(
        &external(&compute, &keys),
        refresh(&keys, &storage_token_body(NEW)),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{text}");
    assert!(!text.contains("k3new"), "{text}");
    assert!(blocked.is_dir());
    assert_eq!(
        held(&compute),
        (Some(OLD.into()), Some(OLD.into())),
        "held token kept"
    );
    assert_eq!(compute.get_status(), ComputeStatus::Running);
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_refresh_never_logs_the_token() {
    let dir = fresh("k3_http_refresh_logs");
    let keys = keys();
    let compute = make_compute(&dir, &keys, Some(OLD), ComputeStatus::Running);
    let router = external(&compute, &keys);
    let (logs, guard) = Logs::capture();
    call(&router, refresh(&keys, &storage_token_body(NEW))).await;
    call(&router, refresh(&keys, &storage_token_body("k3new bad"))).await;
    drop(guard);
    let text = logs.text();
    assert!(!text.is_empty(), "the capture saw the request logs");
    assert!(!text.contains("k3new"), "a token reached the log:\n{text}");
    fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// /configure can't drop or add storage auth (RT4-7, SP6)
// ---------------------------------------------------------------------------

/// `/configure` with the spec (`token` as given), bounded: an accepted request
/// waits for the compute's main thread (absent here), which shows as a timeout;
/// the waiter is then released by moving the status on.
async fn configure(
    compute: &Arc<ComputeNode>,
    keys: &Keys,
    spec: Value,
) -> Option<(StatusCode, String)> {
    let body = json!({
        "spec": spec,
        "compute_ctl_config": { "jwks": { "keys": [] }, "tls": null },
    })
    .to_string();
    let req = post(
        "/configure",
        Some(&format!("Bearer {}", control_token(keys))),
        Some(&body),
    );
    let router = external(compute, keys);
    match tokio::time::timeout(Duration::from_secs(3), router.oneshot(req)).await {
        Ok(res) => {
            let (parts, body) = res.unwrap().into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            Some((parts.status, String::from_utf8_lossy(&bytes).into_owned()))
        }
        Err(_) => None,
    }
}

/// Releases a `/configure` waiter left behind by an accepted request.
fn release(compute: &ComputeNode, to: ComputeStatus) {
    compute.set_status(to);
}

#[tokio::test]
async fn configure_cant_drop_the_storage_token() {
    let keys = keys();
    let mut empty = spec_json(None);
    empty["storage_auth_token"] = json!("");
    let mut null = spec_json(None);
    null["storage_auth_token"] = Value::Null;
    for (what, spec) in [
        ("absent", spec_json(None)),
        ("null", null),
        ("empty", empty),
    ] {
        let dir = fresh(&format!("k3_http_configure_drop_{what}"));
        let compute = make_compute(&dir, &keys, Some(OLD), ComputeStatus::Running);
        fs::write(dir.join(STORAGE_AUTH_TOKEN_FILE), format!("{OLD}\n")).unwrap();
        let answer = configure(&compute, &keys, spec).await;
        if answer.is_none() {
            release(&compute, ComputeStatus::Failed);
        }
        let (status, text) = answer.unwrap_or_else(|| {
            panic!("{what}: /configure accepted a spec without a storage token")
        });
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {text}");
        assert_eq!(
            compute.get_status(),
            ComputeStatus::Running,
            "{what}: status unchanged"
        );
        assert_eq!(
            held(&compute),
            (Some(OLD.into()), Some(OLD.into())),
            "{what}: spec kept"
        );
        assert_eq!(
            file(&dir).as_deref(),
            Some(format!("{OLD}\n").as_str()),
            "{what}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}

#[tokio::test]
async fn configure_cant_add_a_storage_token() {
    let dir = fresh("k3_http_configure_add");
    let keys = keys();
    let compute = make_compute(&dir, &keys, None, ComputeStatus::Running);
    let answer = configure(&compute, &keys, spec_json(Some(NEW))).await;
    if answer.is_none() {
        release(&compute, ComputeStatus::Failed);
    }
    let (status, text) = answer
        .unwrap_or_else(|| panic!("/configure accepted a token on a compute started without one"));
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(!text.contains("k3new"), "{text}");
    assert_eq!(compute.get_status(), ComputeStatus::Running);
    assert_eq!(held(&compute), (None, None));
    assert!(file(&dir).is_none());
    fs::remove_dir_all(&dir).unwrap();
}

/// The guard isn't over-broad: a spec that keeps auth is accepted as before.
#[tokio::test]
async fn configure_with_a_token_is_accepted() {
    let dir = fresh("k3_http_configure_keep");
    let keys = keys();
    let compute = make_compute(&dir, &keys, Some(OLD), ComputeStatus::Running);
    let answer = configure(&compute, &keys, spec_json(Some(NEW))).await;
    let status = compute.get_status();
    release(&compute, ComputeStatus::Running);
    assert!(
        answer.is_none(),
        "accepted, waiting for the reconfigure: {answer:?}"
    );
    assert_eq!(status, ComputeStatus::ConfigurationPending);

    let dir2 = fresh("k3_http_configure_keep_off");
    let compute = make_compute(&dir2, &keys, None, ComputeStatus::Running);
    let answer = configure(&compute, &keys, spec_json(None)).await;
    let status = compute.get_status();
    release(&compute, ComputeStatus::Running);
    assert!(answer.is_none(), "auth off stays off: accepted: {answer:?}");
    assert_eq!(status, ComputeStatus::ConfigurationPending);
    fs::remove_dir_all(&dir).unwrap();
    fs::remove_dir_all(&dir2).unwrap();
}

// ---------------------------------------------------------------------------
// /grants, narrowed (RT4-6): the name rules
// ---------------------------------------------------------------------------

#[tokio::test]
async fn grants_refuse_by_name_before_any_sql() {
    let dir = fresh("k3_http_grants");
    let keys = keys();
    let compute = make_compute(&dir, &keys, None, ComputeStatus::Running);
    let auth = format!("Bearer {}", compute.internal_api_secret());
    let router = internal(&compute);
    let grant = |schema: &str, role: &str, privileges: Value| {
        json!({ "database": "postgres", "schema": schema, "role": role, "privileges": privileges })
            .to_string()
    };

    let mut refused = Vec::new();
    for p in [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
        "CONNECT",
        "TEMPORARY",
        "EXECUTE",
    ] {
        refused.push((
            format!("privilege {p}"),
            grant("app", "app_user", json!([p])),
        ));
    }
    refused.push((
        "USAGE with SELECT".into(),
        grant("app", "app_user", json!(["USAGE", "SELECT"])),
    ));
    for schema in [
        "pg_catalog",
        "information_schema",
        "pg_toast",
        "pg_toast_temp_1",
    ] {
        refused.push((
            format!("schema {schema}"),
            grant(schema, "app_user", json!(["USAGE"])),
        ));
    }
    for role in [
        "cloud_admin",
        "neon_superuser",
        "pg_monitor",
        "pg_read_server_files",
        "pg_database_owner",
        "cb_m_alice",
        "CB_M_Alice",
        "chelabase_realtime",
    ] {
        refused.push((
            format!("grantee {role}"),
            grant("app", role, json!(["USAGE"])),
        ));
    }
    for (what, body) in refused {
        let (status, _, text) = call(&router, post("/grants", Some(&auth), Some(&body))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {text}");
        let json: Value = serde_json::from_str(&text).unwrap();
        assert!(json["error"].is_string(), "{what}: {text}");
    }

    // An ordinary grant gets past the name rules to the database (none here).
    let ok = grant("app", "app_user", json!(["USAGE", "CREATE"]));
    let (status, _, text) = call(&router, post("/grants", Some(&auth), Some(&ok))).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "reached SQL: {text}"
    );
    fs::remove_dir_all(&dir).unwrap();
}
