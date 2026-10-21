//! Fork round 4, K3: what today's interfaces can already express (spec §8
//! "The token file", RT4-2, RT4-11; plan pre-flight 6).
//!
//! - compute_ctl passes no `NEON_AUTH_TOKEN` to any process: the token reaches
//!   Postgres and `--sync-safekeepers` only through the token file.
//! - The spec fetch (`get_config_from_control_plane`) sends
//!   `Compute-Capabilities: storage_token_refresh`.
//! - `compute_ctl` takes `--internal-api-token-file` and
//!   `--storage-auth-token-file`.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;

use compute_tools::spec::get_config_from_control_plane;

const COMPUTE_RS: &str = include_str!("../src/compute.rs");

#[test]
fn compute_ctl_hands_no_token_through_the_environment() {
    let hits: Vec<(usize, &str)> = COMPUTE_RS
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("NEON_AUTH_TOKEN"))
        .map(|(n, l)| (n + 1, l.trim()))
        .collect();
    assert!(
        hits.is_empty(),
        "compute.rs still sets NEON_AUTH_TOKEN: {hits:?}"
    );
}

/// One HTTP request, recorded; the answer is a 404 (compute_ctl doesn't retry it).
fn record_one_request() -> (String, mpsc::Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let line = line.trim_end().to_string();
            if line.is_empty() {
                break;
            }
            lines.push(line);
        }
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .unwrap();
        tx.send(lines).unwrap();
    });
    (format!("http://{addr}"), rx)
}

#[test]
fn the_spec_fetch_advertises_the_storage_token_refresh() {
    let (base, rx) = record_one_request();
    assert!(get_config_from_control_plane(&base, "compute-test").is_err());
    let lines = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    assert!(
        lines[0].starts_with("GET /compute/api/v2/computes/compute-test/spec "),
        "{lines:?}"
    );
    let values: Vec<String> = lines[1..]
        .iter()
        .filter_map(|l| l.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("compute-capabilities"))
        .map(|(_, value)| value.trim().to_string())
        .collect();
    assert_eq!(
        values,
        vec!["storage_token_refresh".to_string()],
        "{lines:?}"
    );
}

#[test]
fn compute_ctl_takes_the_token_file_flags() {
    let out = Command::new(env!("CARGO_BIN_EXE_compute_ctl"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in ["--internal-api-token-file", "--storage-auth-token-file"] {
        assert!(
            help.contains(flag),
            "compute_ctl --help has no {flag}:\n{help}"
        );
    }
}
