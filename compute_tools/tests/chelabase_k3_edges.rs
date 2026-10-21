//! Fork round 4, K3: edge cases beyond the RED set (the coder's own tests).
//!
//! - token files: a reader racing many replacements always reads one whole
//!   token; a missing directory is an error and leaves nothing behind;
//! - `POST /storage_token` from concurrent callers: the file and the held
//!   token end equal (both written under the state lock);
//! - the storage-auth change rule (RT4-7, SP6), exhaustively;
//! - `/configure` with a token outside the alphabet: `400`, nothing changed;
//! - RT4-8: the `Debug` of a parsed spec and of the compute state (what the
//!   promote and apply paths log) carries no token;
//! - a compute started without a token: no storage token file before the sync
//!   (a stale one removed) and an empty path in `postgresql.conf` (P4);
//! - the internal server, launched for real, answers on 127.0.0.1 and is not
//!   reachable on the host's other addresses.

use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use compute_api::responses::{ComputeConfig, ComputeCtlConfig, ComputeStatus};
use compute_tools::compute::{ComputeNode, ComputeNodeParams, ParsedSpec};
use compute_tools::http::server::Server;
use compute_tools::token_file::{STORAGE_AUTH_TOKEN_FILE, write_token_file};
use serde_json::{Value, json};

const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");
const TOKEN: &str = "k3edge.eyJ0IjoxfQ.c2ln";

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn params(dir: &Path, pgbin: &Path, internal_port: u16) -> ComputeNodeParams {
    ComputeNodeParams {
        compute_id: "compute-test".into(),
        connstr: url::Url::parse("postgresql://cloud_admin@127.0.0.1:1/postgres").unwrap(),
        privileged_role_name: "neon_superuser".into(),
        resize_swap_on_bind: false,
        set_disk_quota_for_fs: None,
        pgdata: dir.join("pgdata").to_string_lossy().into(),
        pgbin: pgbin.to_string_lossy().into(),
        pgversion: "17".into(),
        external_http_port: 3080,
        internal_http_port: internal_port,
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
    }
}

fn spec_json(token: Option<&str>) -> Value {
    let mut json: Value = serde_json::from_str(SPEC).unwrap();
    json["safekeeper_connstrings"] = json!(["127.0.0.1:1"]);
    json.as_object_mut().unwrap().remove("pgbouncer_settings");
    match token {
        Some(token) => json["storage_auth_token"] = json!(token),
        None => {
            json.as_object_mut().unwrap().remove("storage_auth_token");
        }
    }
    json
}

fn parsed(token: Option<&str>) -> ParsedSpec {
    ParsedSpec::try_from(
        serde_json::from_value::<compute_api::spec::ComputeSpec>(spec_json(token)).unwrap(),
    )
    .unwrap()
}

fn compute(
    params: ComputeNodeParams,
    token: Option<&str>,
    status: ComputeStatus,
) -> Arc<ComputeNode> {
    let compute = ComputeNode::new(
        params,
        ComputeConfig {
            spec: Some(serde_json::from_value(spec_json(token)).unwrap()),
            compute_ctl_config: ComputeCtlConfig::default(),
        },
    )
    .unwrap();
    compute.set_status(status);
    Arc::new(compute)
}

#[test]
fn a_reader_racing_replacements_reads_whole_tokens() {
    let dir = fresh("k3_edge_race");
    let path = dir.join(STORAGE_AUTH_TOKEN_FILE);
    let tokens: Vec<String> = (0..4)
        .map(|i| format!("k3race{i}.{}", "x".repeat(1000 * (i + 1))))
        .collect();
    write_token_file(&path, &tokens[0]).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let (stop, path, tokens) = (Arc::clone(&stop), path.clone(), tokens.clone());
        std::thread::spawn(move || {
            let mut reads = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let content = fs::read_to_string(&path).expect("the file always exists");
                let token = content.strip_suffix('\n').expect("one whole line");
                assert!(
                    tokens.iter().any(|t| t == token),
                    "a partial token: {} bytes",
                    token.len()
                );
                reads += 1;
            }
            reads
        })
    };
    for i in 0..400 {
        write_token_file(&path, &tokens[i % tokens.len()]).unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    assert!(reader.join().unwrap() > 0);
    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n.to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_missing_directory_is_an_error_and_writes_nothing() {
    let dir = fresh("k3_edge_nodir");
    let path = dir.join("absent").join(STORAGE_AUTH_TOKEN_FILE);
    assert!(write_token_file(&path, TOKEN).is_err());
    assert!(!dir.join("absent").exists());
    fs::remove_dir_all(&dir).unwrap();
}

/// Concurrent refreshes: whichever wins, the file holds the token compute_ctl
/// holds (SP5: its own pageserver calls and the neon extension agree).
#[test]
fn concurrent_refreshes_leave_the_file_and_the_held_token_equal() {
    let dir = fresh("k3_edge_concurrent");
    let compute = compute(
        params(&dir, Path::new("/nonexistent"), 3081),
        Some(TOKEN),
        ComputeStatus::Running,
    );
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let compute = Arc::clone(&compute);
            std::thread::spawn(move || {
                for j in 0..25 {
                    let token = format!("k3conc{i}.{j}");
                    compute
                        .refresh_storage_token(compute_api::spec::StorageAuthToken::new(token))
                        .unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let file = fs::read_to_string(dir.join(STORAGE_AUTH_TOKEN_FILE)).unwrap();
    let state = compute.state.lock().unwrap();
    let pspec = state.pspec.as_ref().unwrap();
    let held = pspec
        .storage_auth_token
        .as_ref()
        .unwrap()
        .as_str()
        .to_owned();
    assert_eq!(file, format!("{held}\n"));
    assert_eq!(
        pspec.spec.storage_auth_token.as_ref().unwrap().as_str(),
        held
    );
    assert_eq!(state.status, ComputeStatus::Running);
    drop(state);
    fs::remove_dir_all(&dir).unwrap();
}

/// RT4-7 and SP6, every combination: only a change of storage auth is refused,
/// and an empty token is no token.
#[test]
fn storage_auth_can_neither_be_dropped_nor_added() {
    let with = parsed(Some(TOKEN));
    let other = parsed(Some("k3edge.other"));
    let without = parsed(None);
    let empty = parsed(Some(""));
    assert!(empty.storage_auth_token.is_none(), "an empty token is none");
    assert!(empty.spec.storage_auth_token.is_none());

    let cases: [(Option<&ParsedSpec>, &ParsedSpec, bool); 8] = [
        (Some(&with), &other, false),
        (Some(&with), &with, false),
        (Some(&with), &without, true),
        (Some(&with), &empty, true),
        (Some(&without), &without, false),
        (Some(&without), &empty, false),
        (Some(&without), &with, true),
        (None, &with, true),
    ];
    for (i, (held, new, refused)) in cases.into_iter().enumerate() {
        let reason = ComputeNode::storage_auth_change_refusal(held, new);
        assert_eq!(reason.is_some(), refused, "case {i}: {reason:?}");
        if let Some(reason) = reason {
            assert!(reason.contains("restart"), "{reason}");
        }
    }
    assert!(ComputeNode::storage_token_refusal(&with).is_none());
    assert!(ComputeNode::storage_token_refusal(&without).is_none());
    assert!(ComputeNode::storage_token_refusal(&parsed(Some("k3 bad"))).is_some());
}

/// RT4-8: what the promote (`{:#?}` of the new spec), the apply (`{:?}` of the
/// spec) and any state dump print never carries the token.
#[test]
fn no_debug_of_parsed_spec_or_state_prints_the_token() {
    let dir = fresh("k3_edge_debug");
    let compute = compute(
        params(&dir, Path::new("/nonexistent"), 3081),
        Some(TOKEN),
        ComputeStatus::Running,
    );
    let state = compute.state.lock().unwrap().clone();
    let pspec = state.pspec.clone().unwrap();
    for text in [
        format!("{pspec:?}"),
        format!("{pspec:#?}"),
        format!("{:#?}", pspec.spec),
        format!("{state:?}"),
        format!("{state:#?}"),
    ] {
        assert!(!text.contains("k3edge"), "a token in a Debug:\n{text}");
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// P4 and RT4-11 for a compute without storage auth: the sync sees an empty
/// path and no token file (a stale one from an earlier start is removed).
#[test]
fn a_start_without_a_token_leaves_no_token_file() {
    let dir = fresh("k3_edge_start_no_token");
    let token_file = dir.join(STORAGE_AUTH_TOKEN_FILE);
    fs::write(&token_file, "k3edge.stale\n").unwrap();
    let pgbin = dir.join("fake_postgres");
    fs::write(
        &pgbin,
        format!(
            "#!/bin/sh\n\
             d='{d}'\n\
             test -e '{t}' && echo PRESENT > \"$d/sync.token\" || echo ABSENT > \"$d/sync.token\"\n\
             cat \"$PGDATA/postgresql.conf\" > \"$d/sync.conf\"\n\
             touch \"$d/sync.done\"\n\
             echo 0/16B9188\n",
            d = dir.display(),
            t = token_file.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&pgbin, fs::Permissions::from_mode(0o755)).unwrap();

    let compute = compute(params(&dir, &pgbin, 3081), None, ComputeStatus::Empty);
    let state = compute.state.lock().unwrap().clone();
    let worker = Arc::clone(&compute);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let _ = worker.prepare_pgdata(&state);
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while !dir.join("sync.done").exists() {
        assert!(
            Instant::now() < deadline,
            "postgres --sync-safekeepers never ran"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        fs::read_to_string(dir.join("sync.token")).unwrap().trim(),
        "ABSENT"
    );
    let conf = fs::read_to_string(dir.join("sync.conf")).unwrap();
    assert!(
        conf.lines()
            .any(|l| l.replace(' ', "") == "neon.storage_auth_token_file=''"),
        "{conf}"
    );
}

/// The internal server, launched as compute_ctl launches it: it answers on
/// 127.0.0.1 (401 without the secret) and nothing listens on the host's
/// non-loopback address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_launched_internal_server_is_loopback_only() {
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let dir = fresh("k3_edge_launch");
    let compute = compute(
        params(&dir, Path::new("/nonexistent"), port),
        None,
        ComputeStatus::Empty,
    );
    Server::Internal { port }.launch(&compute);

    let loopback = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect_timeout(&loopback, Duration::from_millis(200)).is_err() {
        assert!(
            Instant::now() < deadline,
            "the internal server never listened"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let res = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/failpoints"))
        .json(&json!([]))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer"
    );

    // The address a packet to a non-local destination would leave from (no
    // packet is sent: a UDP connect only picks the route).
    let host_ip = UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("10.255.255.255:9").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip());
    if let Ok(ip @ IpAddr::V4(v4)) = host_ip
        && !v4.is_loopback()
        && !v4.is_unspecified()
    {
        let outside = SocketAddr::new(ip, port);
        assert!(
            TcpStream::connect_timeout(&outside, Duration::from_millis(500)).is_err(),
            "the internal server answers on {outside}"
        );
    }
    fs::remove_dir_all(&dir).unwrap();
}

/// `/configure` with a token the file can't hold: refused before anything
/// changes, also on an `empty` compute.
#[tokio::test]
async fn configure_refuses_an_invalid_token() {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use axum::Router;
    use axum::body::Body;
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use http::Request;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, Jwk, JwkSet, OctetKeyPairParameters,
        OctetKeyPairType,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use tower::ServiceExt;

    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let jwks = JwkSet {
        keys: vec![Jwk {
            common: CommonParameters {
                key_id: Some("k3-edge".into()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: EllipticCurve::Ed25519,
                x: BASE64_URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            }),
        }],
    };
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let jwt = jsonwebtoken::encode(
        &Header::new(Algorithm::EdDSA),
        &json!({ "compute_id": "compute-test", "exp": exp }),
        &EncodingKey::from_ed_der(pkcs8.as_ref()),
    )
    .unwrap();

    let dir = fresh("k3_edge_configure_invalid");
    let compute = compute(
        params(&dir, Path::new("/nonexistent"), 3081),
        None,
        ComputeStatus::Empty,
    );
    let router = Router::from(&Server::External {
        port: 3080,
        config: ComputeCtlConfig { jwks, tls: None },
        compute_id: "compute-test".into(),
        instance_id: None,
    })
    .with_state(Arc::clone(&compute));
    let body = json!({
        "spec": spec_json(Some("k3edge bad token")),
        "compute_ctl_config": {"jwks": {"keys": []}, "tls": null},
    })
    .to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/configure")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {jwt}"))
        .body(Body::from(body))
        .unwrap();
    let res = tokio::time::timeout(Duration::from_secs(5), router.oneshot(req))
        .await
        .expect("answered")
        .unwrap();
    assert_eq!(res.status(), http::StatusCode::BAD_REQUEST);
    assert_eq!(compute.get_status(), ComputeStatus::Empty);
    assert!(!dir.join(STORAGE_AUTH_TOKEN_FILE).exists());
    fs::remove_dir_all(&dir).unwrap();
}
