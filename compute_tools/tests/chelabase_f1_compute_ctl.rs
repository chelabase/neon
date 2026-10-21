//! Fork round 4, final fix round (lane F1, item 2): compute_ctl hardening.
//!
//! Pinned behaviour (the code under test; the stale token temp files are in
//! `chelabase_f1_token_tmp.rs`):
//! - The `Debug` of `ComputeSpec` and of `ParsedSpec` never prints
//!   `endpoint_storage_token` (a redacting wrapper, like `StorageAuthToken`);
//!   the spec's JSON keeps it a plain string.
//! - `config::rewrite_config_files` writes `pg_ident.conf` before `pg_hba.conf`
//!   (or rolls back): a failed ident write never leaves a new `pg_hba.conf`
//!   with the old `pg_ident.conf`.
//! - `spec::update_pg_hba` puts the realtime block right after the member
//!   block: a block moved by hand (above the member block, below the `trust`
//!   lines, after the catch-all) is moved back, and lines that sat between the
//!   two blocks follow the realtime block.
//! - The external server's `Authorize`: a token no key of the JWKS verifies
//!   logs at most one WARN line, however many keys the set holds.
//! - `docs/authentication.md`: the compute section names the token files,
//!   never `NEON_AUTH_TOKEN`.
//!
//! `/status`'s capability (SP6) is in `chelabase_k3_http.rs`.

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
use compute_api::spec::{ComputeSpec, MemberLogins};
use compute_tools::compute::{ComputeNode, ComputeNodeParams, ParsedSpec};
use compute_tools::config::rewrite_config_files;
use compute_tools::http::server::Server;
use compute_tools::spec::{member_hba_block, realtime_hba_block, update_pg_hba};
use compute_tools::token_file::{INTERNAL_API_TOKEN_FILE, STORAGE_AUTH_TOKEN_FILE};
use http::{Request, StatusCode};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm,
    OctetKeyPairParameters, OctetKeyPairType, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

const COMPUTE_ID: &str = "compute-f1";
const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");
const STORAGE_TOKEN: &str = "f1storage.eyJ0IjoxfQ.c2ln";
/// The endpoint storage token's value; the needle is a part of it no other
/// field holds.
const ENDPOINT_STORAGE_TOKEN: &str = "f1EndpointStorageNeedle.eyJ0IjoyfQ.c2ln";
const ENDPOINT_STORAGE_NEEDLE: &str = "f1EndpointStorageNeedle";
const ORCH: &str = "chelabase-orchestrator";
const RT_CN: &str = "chelabase-realtime";
const MD5: &str = "host\tall\t\tall\t\tall\t\tmd5\n";
/// The basebackup's sample pg_hba.conf rules.
const BASEBACKUP: &str = "local   all             all                                     trust\n\
host    all             all             127.0.0.1/32            trust\n\
host    all             all             ::1/128                 trust\n\
local   replication     all                                     trust\n\
host    replication     all             127.0.0.1/32            trust\n\
host    replication     all             ::1/128                 trust\n";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

/// A fresh pgdata with `PG_VERSION` 17.
fn pgdata(name: &str) -> PathBuf {
    let dir = fresh(name);
    fs::write(dir.join("PG_VERSION"), "17\n").unwrap();
    dir
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

fn params(dir: &Path) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: COMPUTE_ID.into(),
        // Port 1: nothing listens.
        connstr: url::Url::parse("postgresql://cloud_admin@127.0.0.1:1/postgres").unwrap(),
        privileged_role_name: "neon_superuser".into(),
        resize_swap_on_bind: false,
        set_disk_quota_for_fs: None,
        pgdata: dir.to_string_lossy().into(),
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
        internal_api_token_file: dir.with_file_name(INTERNAL_API_TOKEN_FILE),
        storage_auth_token_file: dir.with_file_name(STORAGE_AUTH_TOKEN_FILE),
    }
}

fn spec_json() -> Value {
    let mut json: Value = serde_json::from_str(SPEC).unwrap();
    json["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
    json["storage_auth_token"] = json!(STORAGE_TOKEN);
    json
}

fn logins(cidrs: &[&str], cns: &[&str]) -> MemberLogins {
    MemberLogins {
        allowed_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        client_cns: cns.iter().map(|s| s.to_string()).collect(),
    }
}

// ---------------------------------------------------------------------------
// The endpoint storage token in Debug (K3 audit, deferred; RT4-8's rule)
// ---------------------------------------------------------------------------

#[test]
fn the_endpoint_storage_token_is_never_printed() {
    let mut json = spec_json();
    json["endpoint_storage_addr"] = json!("127.0.0.1:9993");
    json["endpoint_storage_token"] = json!(ENDPOINT_STORAGE_TOKEN);
    let spec: ComputeSpec = serde_json::from_value(json).unwrap();

    for text in [format!("{spec:?}"), format!("{spec:#?}")] {
        assert!(
            !text.contains(ENDPOINT_STORAGE_NEEDLE),
            "the spec's Debug prints the endpoint storage token:\n{text}"
        );
    }
    // The wire format is unchanged: a plain string.
    let back = serde_json::to_value(&spec).unwrap();
    assert_eq!(
        back["endpoint_storage_token"],
        json!(ENDPOINT_STORAGE_TOKEN)
    );

    let pspec = ParsedSpec::try_from(spec).unwrap();
    for text in [format!("{pspec:?}"), format!("{pspec:#?}")] {
        assert!(
            !text.contains(ENDPOINT_STORAGE_NEEDLE),
            "ParsedSpec's Debug prints the endpoint storage token:\n{text}"
        );
        assert!(!text.contains("f1storage"), "{text}");
    }
}

// ---------------------------------------------------------------------------
// pg_ident.conf before pg_hba.conf (K4 audit, deferred)
// ---------------------------------------------------------------------------

/// The ident file's write fails (its temporary file's name is taken by a
/// directory): `pg_hba.conf` must still be the old one, never new hba lines
/// mapping through an old ident map.
#[test]
fn a_failed_ident_write_leaves_pg_hba_as_it_was() {
    let dir = pgdata("f1_ident_before_hba");
    fs::write(dir.join("postgresql.conf"), "# the running config\n").unwrap();
    fs::write(dir.join("pg_hba.conf"), format!("{BASEBACKUP}{MD5}")).unwrap();
    fs::write(dir.join("pg_ident.conf"), "# hand-written ident\n").unwrap();
    let hba_before = read(&dir.join("pg_hba.conf"));
    let ident_before = read(&dir.join("pg_ident.conf"));
    // The writers' temporary file is `<stem>.tmp.<pid>` in pgdata.
    fs::create_dir(dir.join(format!("pg_ident.tmp.{}", std::process::id()))).unwrap();

    let mut spec: ComputeSpec = serde_json::from_value(spec_json()).unwrap();
    spec.member_logins = Some(logins(&["10.213.4.10/32"], &[ORCH]));
    spec.realtime_logins = Some(logins(&["10.213.4.12/32"], &[RT_CN]));
    let result = rewrite_config_files(&dir, &params(&dir), &spec, None, 3082, &None, false);

    assert!(result.is_err(), "pg_ident.conf can't be written");
    assert_eq!(
        read(&dir.join("pg_hba.conf")),
        hba_before,
        "pg_hba.conf changed although pg_ident.conf couldn't be written"
    );
    assert_eq!(read(&dir.join("pg_ident.conf")), ident_before);
    fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// A hand-moved realtime block (K4 audit, deferred)
// ---------------------------------------------------------------------------

#[test]
fn a_hand_moved_realtime_block_goes_back_after_the_member_block() {
    let ml = logins(&["10.213.4.10/32"], &[ORCH]);
    let rl = logins(&["10.213.4.12/32"], &[RT_CN]);
    let member = member_hba_block(Some(&ml), true).unwrap();
    let rt = realtime_hba_block(Some(&rl), true).unwrap();
    let before = "# edited by hand, above the blocks\n";
    let trust_all = "host    all             all             0.0.0.0/0               trust\n";

    let cases = [
        (
            "above the member block",
            format!("{before}{rt}{member}{BASEBACKUP}{MD5}"),
            format!("{before}{member}{rt}{BASEBACKUP}{MD5}"),
        ),
        (
            "below the trust lines",
            format!("{member}{BASEBACKUP}{rt}{MD5}"),
            format!("{member}{rt}{BASEBACKUP}{MD5}"),
        ),
        (
            "a trust line between the blocks",
            format!("{member}{trust_all}{rt}{BASEBACKUP}{MD5}"),
            format!("{member}{rt}{trust_all}{BASEBACKUP}{MD5}"),
        ),
        (
            "after the catch-all",
            format!("{member}{BASEBACKUP}{MD5}{rt}"),
            format!("{member}{rt}{BASEBACKUP}{MD5}"),
        ),
    ];
    for (i, (what, text, want)) in cases.iter().enumerate() {
        let dir = pgdata(&format!("f1_rt_moved_{i}"));
        let hba = dir.join("pg_hba.conf");
        fs::write(&hba, text).unwrap();
        update_pg_hba(&dir, None, Some(&ml), Some(&rl), true).unwrap();
        assert_eq!(&read(&hba), want, "{what}");
        update_pg_hba(&dir, None, Some(&ml), Some(&rl), true).unwrap();
        assert_eq!(&read(&hba), want, "{what}: idempotent");
        fs::remove_dir_all(&dir).unwrap();
    }
}

// ---------------------------------------------------------------------------
// One warning per failed token, not one per JWKS key (K4 audit, deferred)
// ---------------------------------------------------------------------------

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
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// A fresh Ed25519 pair: its PKCS#8 document and its JWK.
fn ed25519_key(kid: &str) -> (Vec<u8>, Jwk) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: None,
            key_algorithm: Some(KeyAlgorithm::EdDSA),
            key_id: Some(kid.into()),
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
    (pkcs8.as_ref().to_vec(), jwk)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The external router of a compute whose JWKS holds `keys` keys.
fn external_with_keys(dir: &Path, keys: usize) -> Router {
    let jwks = JwkSet {
        keys: (0..keys)
            .map(|i| ed25519_key(&format!("f1-key-{i}")).1)
            .collect(),
    };
    let config = ComputeCtlConfig { jwks, tls: None };
    let compute = ComputeNode::new(
        params(&dir.join("pgdata")),
        ComputeConfig {
            spec: Some(serde_json::from_value(spec_json()).unwrap()),
            compute_ctl_config: config.clone(),
        },
    )
    .unwrap();
    compute.set_status(ComputeStatus::Running);
    Router::from(&Server::External {
        port: 3080,
        config,
        compute_id: COMPUTE_ID.into(),
        instance_id: None,
    })
    .with_state(Arc::new(compute))
}

/// The WARN lines (and the whole log) of `bad.len()` refused `/status` calls.
async fn warnings_for(router: &Router, bad: &[String]) -> (usize, String) {
    let (logs, guard) = Logs::capture();
    for token in bad {
        let req = Request::builder()
            .method("GET")
            .uri("/status")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(20), router.clone().oneshot(req))
            .await
            .expect("the route answered within 20 s")
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "a bad token");
    }
    drop(guard);
    let text = logs.text();
    let warnings = text.lines().filter(|l| l.contains("WARN")).count();
    (warnings, text)
}

#[tokio::test]
async fn a_bad_token_logs_one_warning_whatever_the_key_count() {
    // Signed by a key the compute doesn't know, and not a JWT at all.
    let (stranger, _) = ed25519_key("f1-stranger");
    let foreign = jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        &json!({ "compute_id": COMPUTE_ID, "exp": now() + 3600 }),
        &EncodingKey::from_ed_der(&stranger),
    )
    .unwrap();
    let bad: Vec<String> = vec![
        foreign.clone(),
        foreign.clone(),
        "f1NotAJwtNeedle".into(),
        "eyJhbGciOiJFZERTQSJ9.e30.ZjFCYWRTaWc".into(),
    ];

    let mut counts = Vec::new();
    for keys in [1, 6] {
        let dir = fresh(&format!("f1_jwks_warn_{keys}"));
        let (warnings, text) = warnings_for(&external_with_keys(&dir, keys), &bad).await;
        assert!(
            warnings <= bad.len(),
            "{keys} JWKS keys: {warnings} WARN lines for {} refused tokens (at most one each):\n{text}",
            bad.len()
        );
        assert!(
            !text.contains("f1NotAJwtNeedle"),
            "a token was logged:\n{text}"
        );
        assert!(!text.contains(&foreign), "a token was logged:\n{text}");
        counts.push(warnings);
        fs::remove_dir_all(&dir).unwrap();
    }
    assert_eq!(
        counts[0], counts[1],
        "the WARN lines of a refused token grow with the number of JWKS keys"
    );
}

// ---------------------------------------------------------------------------
// docs/authentication.md (K3 audit, deferred)
// ---------------------------------------------------------------------------

#[test]
fn the_compute_docs_name_the_token_files() {
    let doc = include_str!("../../docs/authentication.md");
    let start = doc.find("### Compute").expect("a compute section");
    let end = start
        + doc[start..]
            .find("### Pageserver")
            .expect("a pageserver section");
    let compute = &doc[start..end];
    assert!(
        !compute.contains("NEON_AUTH_TOKEN"),
        "the compute section still describes NEON_AUTH_TOKEN:\n{compute}"
    );
    for name in [
        "neon.storage_auth_token_file",
        "neon.compute_ctl_token_file",
    ] {
        assert!(
            compute.contains(name),
            "the compute section doesn't name {name}"
        );
    }
}
