//! Fork round 4, K3 fix round: the internal server's listeners fail closed.
//!
//! Pinned interface (the code under test):
//! - `Server::launch(self, compute: &Arc<ComputeNode>) -> anyhow::Result<()>`,
//!   synchronous: it binds every listen address before it returns (so a
//!   connection right after `Ok` is accepted) and only then spawns the serving
//!   tasks; a bind error is returned, naming the address, and `ComputeNode::run`
//!   returns it with `?`, so compute_ctl fails its start. On an error no
//!   listener is left bound.
//! - The internal server's `[::1]:<port>` is tolerated only when the host has no
//!   IPv6 loopback (`EADDRNOTAVAIL`, `EAFNOSUPPORT`); any other error (a squatter's
//!   `EADDRINUSE` included) fails the start: a local process holding `[::1]:3081`
//!   would otherwise receive the bearer of every caller dialling `localhost`.
//!
//! The ci-local container has `::1` on `lo` (checked: `/proc/net/if_inet6`,
//! `disable_ipv6 = 0`). On a host without it the `[::1]` squatter can't bind; the
//! test then proves the tolerated path instead (the start succeeds).

use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use compute_api::responses::{ComputeConfig, ComputeCtlConfig, ComputeStatus};
use compute_tools::compute::{ComputeNode, ComputeNodeParams};
use compute_tools::http::server::Server;
use compute_tools::token_file::STORAGE_AUTH_TOKEN_FILE;
use serde_json::{Value, json};

const SPEC: &str = include_str!("../../libs/compute_api/tests/cluster_spec.json");

/// The base's `launch` returned `()` (binding inside a spawned task); the fix
/// returns `anyhow::Result<()>`. This lets the RED run against the base show the
/// behaviour (a start that "succeeds") instead of a compile error.
trait Launched {
    fn result(self) -> anyhow::Result<()>;
}

impl Launched for () {
    fn result(self) -> anyhow::Result<()> {
        Ok(())
    }
}

impl Launched for anyhow::Result<()> {
    fn result(self) -> anyhow::Result<()> {
        self
    }
}

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn compute(dir: &Path, internal_port: u16) -> Arc<ComputeNode> {
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

fn v4(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn v6(port: u16) -> SocketAddr {
    SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))
}

/// Whether binding `[::1]` failed because the host has no IPv6 loopback.
fn no_ipv6_loopback(e: &std::io::Error) -> bool {
    e.kind() == ErrorKind::AddrNotAvailable
        || e.raw_os_error() == Some(nix::errno::Errno::EAFNOSUPPORT as i32)
}

/// Whether this host has `::1` (binding it with port 0 works).
fn has_ipv6_loopback() -> bool {
    match TcpListener::bind(v6(0)) {
        Ok(_) => true,
        Err(e) if no_ipv6_loopback(&e) => false,
        Err(e) => panic!("binding [::1]:0: {e}"),
    }
}

/// A port free on 127.0.0.1 (and on ::1 when the host has it), released.
fn free_port() -> u16 {
    for _ in 0..50 {
        let port = TcpListener::bind(v4(0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if !has_ipv6_loopback() || TcpListener::bind(v6(port)).is_ok() {
            return port;
        }
    }
    panic!("no port free on both loopbacks");
}

fn error_text(e: &anyhow::Error) -> String {
    format!("{e:#}")
}

/// A local process squatting `[::1]:<port>` before compute_ctl starts: the
/// internal server refuses to start rather than leave `localhost` callers to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_squatted_ipv6_loopback_fails_the_start() {
    let dir = fresh("k3fix_squat_v6");
    let squatter = match TcpListener::bind(v6(0)) {
        Ok(listener) => listener,
        Err(e) if no_ipv6_loopback(&e) => {
            // No IPv6 loopback: the tolerated path, the start succeeds on 127.0.0.1.
            let port = free_port();
            let result = Server::Internal { port }
                .launch(&compute(&dir, port))
                .result();
            assert!(result.is_ok(), "no ::1 must be tolerated: {result:?}");
            assert!(TcpStream::connect_timeout(&v4(port), Duration::from_secs(2)).is_ok());
            eprintln!("this host has no ::1; proved the tolerated path only");
            fs::remove_dir_all(&dir).unwrap();
            return;
        }
        Err(e) => panic!("binding the [::1] squatter: {e}"),
    };
    let port = squatter.local_addr().unwrap().port();
    assert!(
        TcpListener::bind(v4(port)).is_ok(),
        "127.0.0.1:{port} is taken by someone else; rerun"
    );

    let result = Server::Internal { port }
        .launch(&compute(&dir, port))
        .result();
    assert!(
        result.is_err(),
        "the internal server started while [::1]:{port} was held by another process"
    );
    let text = error_text(&result.unwrap_err());
    assert!(
        text.contains(&v6(port).to_string()),
        "the error names [::1]:{port}: {text}"
    );

    // Nothing left half-started: 127.0.0.1:<port> was released (or never bound).
    let rebound = TcpListener::bind(v4(port));
    assert!(
        rebound.is_ok(),
        "the failed start left 127.0.0.1:{port} bound: {rebound:?}"
    );
    drop(squatter);
    fs::remove_dir_all(&dir).unwrap();
}

/// A squatter on `127.0.0.1:<port>`: the start fails (returned, not a panic in a
/// spawned task that leaves the compute running with no internal server).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_squatted_ipv4_loopback_fails_the_start() {
    let dir = fresh("k3fix_squat_v4");
    let ipv6 = has_ipv6_loopback();
    let (squatter, port) = loop {
        let squatter = TcpListener::bind(v4(0)).unwrap();
        let port = squatter.local_addr().unwrap().port();
        if !ipv6 || TcpListener::bind(v6(port)).is_ok() {
            break (squatter, port);
        }
    };

    let result = Server::Internal { port }
        .launch(&compute(&dir, port))
        .result();
    assert!(
        result.is_err(),
        "the internal server's start succeeded while 127.0.0.1:{port} was held by another process"
    );
    let text = error_text(&result.unwrap_err());
    assert!(
        text.contains(&v4(port).to_string()),
        "the error names 127.0.0.1:{port}: {text}"
    );

    if ipv6 {
        let rebound = TcpListener::bind(v6(port));
        assert!(
            rebound.is_ok(),
            "the failed start left [::1]:{port} bound: {rebound:?}"
        );
    }
    drop(squatter);
    fs::remove_dir_all(&dir).unwrap();
}

/// `Ok` means bound: a connection right after `launch` returns is accepted on
/// every loopback the host has, without waiting for a spawned task, and the
/// server behind it is the internal one (`401` without the bearer).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn launch_returns_with_every_listener_bound() {
    let dir = fresh("k3fix_bound");
    let port = free_port();
    let result = Server::Internal { port }
        .launch(&compute(&dir, port))
        .result();
    assert!(result.is_ok(), "{result:?}");

    let mut addrs = vec![v4(port)];
    if has_ipv6_loopback() {
        addrs.push(v6(port));
    }
    for addr in &addrs {
        // A bound listener with no accept loop yet still completes the handshake.
        let connected = TcpStream::connect_timeout(addr, Duration::from_millis(500));
        assert!(
            connected.is_ok(),
            "{addr} not bound when launch returned: {connected:?}"
        );
    }
    for addr in &addrs {
        let res = reqwest::Client::new()
            .post(format!("http://{addr}/grants"))
            .json(&json!({}))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED, "{addr}");
    }
    fs::remove_dir_all(&dir).unwrap();
}
