//! Fork round 4, K4: edge cases beyond the RED set (the coder's own tests).
//!
//! - The bearer header: scheme case, spaces and surrounding whitespace accepted;
//!   two `Authorization` headers, a tab after the scheme refused (401).
//! - `HEAD` on a metrics route with a `metrics` token is let through; an empty
//!   JWKS is a 401, not a panic; a `metrics` token signed by a key without
//!   `kid` opens `/metrics`.
//! - pg_hba/pg_ident: a realtime block moved above the member block by hand is
//!   replaced where it is; a CRLF realtime block is replaced; stray unmarked
//!   `chelabase_realtime` ident lines go when the realtime map is first
//!   written (no CN stays mapped outside the block) and are kept once the
//!   block exists; an empty `client_cns` in the hba block alone is accepted
//!   (the ident lines refuse it).

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
use compute_api::spec::MemberLogins;
use compute_tools::compute::{ComputeNode, ComputeNodeParams};
use compute_tools::http::server::Server;
use compute_tools::spec::{
    member_hba_block, member_ident_lines, realtime_hba_block, realtime_ident_lines, update_pg_hba,
    update_pg_ident,
};
use compute_tools::token_file::{INTERNAL_API_TOKEN_FILE, STORAGE_AUTH_TOKEN_FILE};
use http::{Method, Request, StatusCode};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

const COMPUTE_ID: &str = "compute-k4-edges";
const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn params(dir: &Path) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: COMPUTE_ID.into(),
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

/// An Ed25519 signing key and its JWK.
fn new_key(kid: Option<&str>) -> (EncodingKey, Jwk) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: None,
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            key_id: kid.map(str::to_owned),
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
    (EncodingKey::from_ed_der(pkcs8.as_ref()), jwk)
}

fn jwt(key: &EncodingKey, claims: Value) -> String {
    jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, key).unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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

async fn call(router: &Router, method: Method, uri: &str, auth: &[&str]) -> StatusCode {
    let mut req = Request::builder().method(method).uri(uri);
    for a in auth {
        req = req.header("authorization", *a);
    }
    let req = req.body(Body::empty()).unwrap();
    let router = router.clone();
    let res = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::spawn(async move { router.oneshot(req).await }),
    )
    .await
    .expect("answered within 20 s")
    .expect("no panic")
    .unwrap();
    let status = res.status();
    if status == StatusCode::UNAUTHORIZED {
        assert!(
            res.headers()
                .get("www-authenticate")
                .is_some_and(|v| v.as_bytes().starts_with(b"Bearer")),
            "a 401 without the challenge"
        );
    }
    status
}

#[tokio::test]
async fn bearer_header_spellings() {
    let dir = fresh("k4_edges_header");
    let (key, jwk) = new_key(Some("k4"));
    let router = external(&dir, vec![jwk]);
    let token = jwt(
        &key,
        json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 }),
    );
    for accepted in [
        format!("Bearer {token}"),
        format!("bearer {token}"),
        format!("BEARER {token}"),
        format!("Bearer    {token}"),
        format!(" Bearer {token} "),
    ] {
        assert_eq!(
            call(&router, Method::GET, "/status", &[&accepted]).await,
            StatusCode::OK,
            "{accepted:.30}"
        );
    }
    let one = format!("Bearer {token}");
    for refused in [
        vec![one.clone(), one.clone()],
        vec![format!("Bearer\t{token}")],
        vec![format!("Bearer{token}")],
        vec![format!("Bearer {token}x")],
    ] {
        let refs: Vec<&str> = refused.iter().map(String::as_str).collect();
        assert_eq!(
            call(&router, Method::GET, "/status", &refs).await,
            StatusCode::UNAUTHORIZED,
            "{:.30}",
            refused[0]
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn metrics_token_edges() {
    let dir = fresh("k4_edges_metrics");
    let (key, jwk) = new_key(None);
    let router = external(&dir, vec![jwk]);
    let metrics = format!("Bearer {}", jwt(&key, json!({ "scope": "metrics" })));
    assert_eq!(
        call(&router, Method::GET, "/metrics", &[&metrics]).await,
        StatusCode::OK,
        "a metrics token signed by a key without kid"
    );
    assert_eq!(
        call(&router, Method::HEAD, "/metrics", &[&metrics]).await,
        StatusCode::OK,
        "HEAD /metrics"
    );
    // A metrics token whose `exp` is still in the future is fine; one in the
    // past is refused on the metrics routes as everywhere.
    let fresh_exp = format!(
        "Bearer {}",
        jwt(&key, json!({ "scope": "metrics", "exp": now() + 60 }))
    );
    assert_eq!(
        call(&router, Method::GET, "/metrics", &[&fresh_exp]).await,
        StatusCode::OK
    );
    let expired = format!(
        "Bearer {}",
        jwt(&key, json!({ "scope": "metrics", "exp": now() - 3600 }))
    );
    for route in ["/metrics", "/autoscaling_metrics", "/status"] {
        assert_eq!(
            call(&router, Method::GET, route, &[&expired]).await,
            StatusCode::UNAUTHORIZED,
            "{route}, expired"
        );
    }
    // An unknown scope doesn't decode: 401, never a fall-through to the
    // compute_id check.
    let unknown = format!(
        "Bearer {}",
        jwt(
            &key,
            json!({ "scope": "compute_ctl:metrics", "compute_id": COMPUTE_ID })
        )
    );
    assert_eq!(
        call(&router, Method::GET, "/status", &[&unknown]).await,
        StatusCode::UNAUTHORIZED
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn an_empty_jwks_refuses_everything() {
    let dir = fresh("k4_edges_empty_jwks");
    let (key, _) = new_key(Some("k4"));
    let router = external(&dir, vec![]);
    let token = format!(
        "Bearer {}",
        jwt(
            &key,
            json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 })
        )
    );
    for route in ["/status", "/metrics"] {
        assert_eq!(
            call(&router, Method::GET, route, &[&token]).await,
            StatusCode::UNAUTHORIZED,
            "{route}"
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// pg_hba / pg_ident
// ---------------------------------------------------------------------------

const MD5: &str = "host\tall\t\tall\t\tall\t\tmd5\n";

fn logins(cidrs: &[&str], cns: &[&str]) -> MemberLogins {
    MemberLogins {
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        client_cns: cns.iter().map(|s| s.to_string()).collect(),
    }
}

fn pgdata(name: &str) -> PathBuf {
    let dir = fresh(name);
    fs::write(dir.join("PG_VERSION"), "17\n").unwrap();
    dir
}

#[test]
fn a_realtime_block_above_the_member_block_is_replaced_where_it_is() {
    let dir = pgdata("k4_edges_moved");
    let hba = dir.join("pg_hba.conf");
    let ml = logins(&["10.213.4.10/32"], &["chelabase-orchestrator"]);
    let r1 = logins(&["10.213.4.12/32"], &["chelabase-realtime"]);
    let r2 = logins(&["10.213.4.13/32"], &["chelabase-realtime"]);
    let member = member_hba_block(Some(&ml), true).unwrap();
    fs::write(
        &hba,
        format!(
            "{}{member}{MD5}",
            realtime_hba_block(Some(&r1), true).unwrap()
        ),
    )
    .unwrap();
    update_pg_hba(&dir, None, Some(&ml), Some(&r2), true).unwrap();
    assert_eq!(
        fs::read_to_string(&hba).unwrap(),
        format!(
            "{}{member}{MD5}",
            realtime_hba_block(Some(&r2), true).unwrap()
        )
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_crlf_realtime_block_is_replaced() {
    let dir = pgdata("k4_edges_crlf");
    let hba = dir.join("pg_hba.conf");
    let ml = logins(&["10.213.4.10/32"], &["chelabase-orchestrator"]);
    let r1 = logins(&["10.213.4.12/32"], &["chelabase-realtime"]);
    let member = member_hba_block(Some(&ml), true).unwrap();
    let crlf = realtime_hba_block(Some(&r1), true)
        .unwrap()
        .replace('\n', "\r\n");
    fs::write(&hba, format!("{member}{crlf}{MD5}")).unwrap();
    update_pg_hba(&dir, None, Some(&ml), None, true).unwrap();
    assert_eq!(
        fs::read_to_string(&hba).unwrap(),
        format!("{member}{}{MD5}", realtime_hba_block(None, true).unwrap())
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn stray_realtime_ident_lines_go_with_the_first_block() {
    let dir = pgdata("k4_edges_stray_ident");
    let ident = dir.join("pg_ident.conf");
    let ml = logins(&[], &["chelabase-orchestrator"]);
    let rl = logins(&[], &["chelabase-realtime"]);
    fs::write(
        &ident,
        "mymap\tbob\tbob\nchelabase_realtime\tevil-cn\tchelabase_realtime\n",
    )
    .unwrap();
    update_pg_ident(&dir, None, Some(&ml), Some(&rl)).unwrap();
    let block = |rl: Option<&MemberLogins>| {
        format!(
            "# chelabase: realtime certificate map (chelabase_realtime)\n{}\
             # chelabase: end of realtime certificate map\n",
            realtime_ident_lines(rl).unwrap()
        )
    };
    let member = format!(
        "# chelabase: member certificate map (chelabase_member)\n{}\
         # chelabase: end of member certificate map\n",
        member_ident_lines(Some(&ml)).unwrap()
    );
    let text = fs::read_to_string(&ident).unwrap();
    assert_eq!(
        text,
        format!("{member}{}mymap\tbob\tbob\n", block(Some(&rl)))
    );
    assert!(!text.contains("evil-cn"), "{text}");

    // Once the block exists, a line added below it by hand is kept.
    fs::write(
        &ident,
        format!("{text}chelabase_realtime\tmine\tchelabase_realtime\n"),
    )
    .unwrap();
    update_pg_ident(&dir, None, Some(&ml), None).unwrap();
    assert_eq!(
        fs::read_to_string(&ident).unwrap(),
        format!(
            "{member}{}mymap\tbob\tbob\nchelabase_realtime\tmine\tchelabase_realtime\n",
            block(None)
        )
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_hba_block_alone_takes_an_empty_cn_list() {
    let rl = logins(&["10.213.4.12/32"], &[]);
    assert!(realtime_hba_block(Some(&rl), true).is_ok());
    let err = realtime_ident_lines(Some(&rl)).unwrap_err();
    assert!(format!("{err:#}").contains("realtime_logins: client_cns is empty"));
}
