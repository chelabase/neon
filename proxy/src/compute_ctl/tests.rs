//! K8: the `--compute-ctl-token-file` bearer on every compute_ctl call.
//!
//! Pinned items under test (all new):
//! - `LocalBackend::new(postgres_addr, compute_ctl_url, compute_ctl_token_file: Option<Utf8PathBuf>)`;
//! - `ComputeCtlApi::token_file(&self) -> Option<&Utf8Path>`.
//!
//! The reader alphabet is the shared token-file one: one line of
//! `[A-Za-z0-9._~+/=-]`, 1-8191 bytes, one trailing `\n` stripped, whole file
//! at most 8 KiB. The file is read before each call, never cached.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use camino::Utf8PathBuf;
use camino_tempfile::Utf8TempDir;
use hyper::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{ComputeCtlError, ExtensionInstallRequest};
use crate::auth::backend::local::LocalBackend;
use crate::url::ApiUrl;

const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A stand-in for compute_ctl's internal server: it answers 200 only to
/// exactly one `Authorization: Bearer <secret>` and records the
/// `Authorization` headers of every request it sees (one entry per request).
struct FakeComputeCtl {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Vec<String>>>>,
}

impl FakeComputeCtl {
    async fn start(secret: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let head_end = loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let mut auth = Vec::new();
                    let mut content_length = 0usize;
                    for line in head.split("\r\n").skip(1) {
                        let Some((name, value)) = line.split_once(':') else {
                            continue;
                        };
                        let value = value.trim().to_string();
                        match name.to_ascii_lowercase().as_str() {
                            "authorization" => auth.push(value),
                            "content-length" => content_length = value.parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                    while buf.len() < head_end + content_length {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let ok = auth.len() == 1 && auth[0] == format!("Bearer {secret}");
                    seen.lock().unwrap().push(auth);
                    let (status, body) = if ok {
                        ("200 OK", "{}")
                    } else {
                        ("401 Unauthorized", r#"{"error":"unauthorized"}"#)
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    drop(sock.write_all(resp.as_bytes()).await);
                    drop(sock.shutdown().await);
                });
            }
        });
        Self { addr, seen }
    }

    fn backend(&self, token_file: Option<Utf8PathBuf>) -> LocalBackend {
        let url: ApiUrl = format!("http://{}/", self.addr).parse().unwrap();
        LocalBackend::new("127.0.0.1:5432".parse().unwrap(), url, token_file)
    }

    fn requests(&self) -> Vec<Vec<String>> {
        self.seen.lock().unwrap().clone()
    }
}

async fn call(backend: &LocalBackend) -> Result<(), ComputeCtlError> {
    backend
        .compute_ctl
        .install_extension(&ExtensionInstallRequest {
            extension: "pg_session_jwt",
            database: "postgres".into(),
            version: "1.0.0",
        })
        .await
        .map(|_| ())
}

fn is_refused(r: &Result<(), ComputeCtlError>) -> bool {
    matches!(r, Err(ComputeCtlError::Request { status, .. }) if *status == StatusCode::UNAUTHORIZED)
}

fn token_path(dir: &Utf8TempDir) -> Utf8PathBuf {
    dir.path().join("compute_ctl_internal.token")
}

/// The call goes out with no `Authorization` header at all and is refused.
async fn assert_no_header_and_refused(fake: &FakeComputeCtl, backend: &LocalBackend, why: &str) {
    let before = fake.requests().len();
    let r = call(backend).await;
    assert!(is_refused(&r), "{why}: expected a 401, got {r:?}");
    let reqs = fake.requests();
    assert_eq!(reqs.len(), before + 1, "{why}: one request expected");
    assert_eq!(
        reqs[before],
        Vec::<String>::new(),
        "{why}: no Authorization header may be sent"
    );
}

#[tokio::test]
async fn the_bearer_comes_from_the_file() {
    let fake = FakeComputeCtl::start(SECRET).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    std::fs::write(&path, format!("{SECRET}\n")).unwrap();
    let backend = fake.backend(Some(path.clone()));
    assert_eq!(backend.compute_ctl.token_file(), Some(path.as_path()));

    call(&backend).await.unwrap();
    assert_eq!(fake.requests(), vec![vec![format!("Bearer {SECRET}")]]);
}

#[tokio::test]
async fn the_trailing_newline_is_optional_but_only_one_is_stripped() {
    let fake = FakeComputeCtl::start("abc").await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    let backend = fake.backend(Some(path.clone()));

    std::fs::write(&path, "abc").unwrap();
    call(&backend).await.unwrap();
    std::fs::write(&path, "abc\n").unwrap();
    call(&backend).await.unwrap();

    std::fs::write(&path, "abc\n\n").unwrap();
    assert_no_header_and_refused(&fake, &backend, "two trailing newlines").await;
}

#[tokio::test]
async fn every_alphabet_character_is_sent_verbatim() {
    let token = "AZaz09._~+/=-";
    let fake = FakeComputeCtl::start(token).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    std::fs::write(&path, format!("{token}\n")).unwrap();
    call(&fake.backend(Some(path))).await.unwrap();
    assert_eq!(fake.requests(), vec![vec![format!("Bearer {token}")]]);
}

#[tokio::test]
async fn a_rewritten_file_takes_effect_on_the_next_call() {
    let fake = FakeComputeCtl::start("second").await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    let backend = fake.backend(Some(path.clone()));

    // A compute_ctl restart draws a new secret: the first one is now stale.
    std::fs::write(&path, "first\n").unwrap();
    let r = call(&backend).await;
    assert!(is_refused(&r), "the old secret must be refused: {r:?}");

    // In-place rewrite (same inode, same size would also defeat an mtime cache).
    std::fs::write(&path, "second\n").unwrap();
    call(&backend).await.unwrap();

    // compute_ctl's own way: temp file + rename (new inode).
    let tmp = dir.path().join("compute_ctl_internal.token.tmp.1");
    std::fs::write(&tmp, "second\n").unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    call(&backend).await.unwrap();

    let reqs = fake.requests();
    assert_eq!(
        reqs,
        vec![
            vec!["Bearer first".to_string()],
            vec!["Bearer second".to_string()],
            vec!["Bearer second".to_string()],
        ]
    );
}

#[tokio::test]
async fn same_size_rewrite_within_one_instant_is_still_seen() {
    let fake = FakeComputeCtl::start("bbbbbbbb").await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    let backend = fake.backend(Some(path.clone()));
    for _ in 0..5 {
        std::fs::write(&path, "aaaaaaaa\n").unwrap();
        let r = call(&backend).await;
        assert!(is_refused(&r), "{r:?}");
        std::fs::write(&path, "bbbbbbbb\n").unwrap();
        call(&backend).await.unwrap();
    }
}

#[tokio::test]
async fn no_flag_means_no_header() {
    let fake = FakeComputeCtl::start(SECRET).await;
    let backend = fake.backend(None);
    assert_eq!(backend.compute_ctl.token_file(), None);
    assert_no_header_and_refused(&fake, &backend, "no token file configured").await;
}

#[tokio::test]
async fn a_missing_file_is_no_startup_error_and_no_header() {
    let fake = FakeComputeCtl::start(SECRET).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);

    // SP19: construction with an absent file neither fails nor panics.
    let backend = fake.backend(Some(path.clone()));
    assert_no_header_and_refused(&fake, &backend, "file absent at startup").await;

    // The file appears later (compute_ctl started): the next call uses it.
    std::fs::write(&path, format!("{SECRET}\n")).unwrap();
    call(&backend).await.unwrap();

    // And it vanishes again (a restart in progress): back to no header.
    std::fs::remove_file(&path).unwrap();
    assert_no_header_and_refused(&fake, &backend, "file removed").await;
}

#[tokio::test]
async fn an_invalid_file_means_no_header() {
    let fake = FakeComputeCtl::start(SECRET).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    let backend = fake.backend(Some(path.clone()));

    let mut cases: Vec<(String, Vec<u8>)> = vec![
        ("empty file".into(), b"".to_vec()),
        ("only a newline".into(), b"\n".to_vec()),
        ("two lines".into(), b"abc\ndef\n".to_vec()),
        ("space inside".into(), b"abc def\n".to_vec()),
        ("leading space".into(), b" abc\n".to_vec()),
        ("CRLF".into(), b"abc\r\n".to_vec()),
        ("header injection".into(), b"abc\r\nX-Evil: 1\n".to_vec()),
        ("NUL".into(), b"ab\0c\n".to_vec()),
        ("invalid utf-8".into(), vec![0xff, 0xfe, b'a', b'\n']),
        (
            "8192 characters (one over)".into(),
            [vec![b'a'; 8192], b"\n".to_vec()].concat(),
        ),
        ("1 MiB file".into(), vec![b'a'; 1 << 20]),
    ];
    for c in [
        ' ', '\t', '"', '\'', ';', ',', '\\', ':', '@', '%', '\r', '\u{e9}', '\u{7f}', '<', '*',
    ] {
        cases.push((
            format!("character {c:?}"),
            format!("ab{c}cd\n").into_bytes(),
        ));
    }
    for (why, bytes) in cases {
        std::fs::write(&path, &bytes).unwrap();
        assert_no_header_and_refused(&fake, &backend, &why).await;
    }

    // A directory in place of the file.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_no_header_and_refused(&fake, &backend, "a directory").await;
}

#[tokio::test]
async fn the_largest_valid_token_is_sent() {
    let token = "a".repeat(8191);
    let leaked: &'static str = Box::leak(token.clone().into_boxed_str());
    let fake = FakeComputeCtl::start(leaked).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    std::fs::write(&path, format!("{token}\n")).unwrap();
    call(&fake.backend(Some(path))).await.unwrap();
    assert_eq!(fake.requests(), vec![vec![format!("Bearer {token}")]]);
}

#[tokio::test]
async fn a_recovered_file_works_after_an_invalid_one() {
    let fake = FakeComputeCtl::start(SECRET).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    let backend = fake.backend(Some(path.clone()));
    std::fs::write(&path, "bad token\n").unwrap();
    assert_no_header_and_refused(&fake, &backend, "invalid").await;
    std::fs::write(&path, format!("{SECRET}\n")).unwrap();
    call(&backend).await.unwrap();
}

#[tokio::test]
async fn grants_carry_the_bearer_too() {
    use super::{Privilege, SetRoleGrantsRequest};

    let fake = FakeComputeCtl::start("grants-secret").await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    std::fs::write(&path, "grants-secret\n").unwrap();
    let backend = fake.backend(Some(path));
    backend
        .compute_ctl
        .grant_role(&SetRoleGrantsRequest {
            database: "postgres".into(),
            schema: "public",
            privileges: vec![Privilege::Usage],
            role: "app".into(),
        })
        .await
        .unwrap();
    assert_eq!(
        fake.requests(),
        vec![vec!["Bearer grants-secret".to_string()]]
    );
}

#[tokio::test]
#[tracing_test::traced_test]
async fn the_token_never_reaches_logs_or_errors() {
    let secret = "SECRETTOKENVALUE123";
    let fake = FakeComputeCtl::start("a-different-secret").await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    let backend = fake.backend(Some(path.clone()));

    // Valid file, wrong secret: refused.
    std::fs::write(&path, format!("{secret}\n")).unwrap();
    let r = call(&backend).await;
    assert!(is_refused(&r));
    let err = r.unwrap_err();
    for text in [format!("{err}"), format!("{err:?}"), format!("{err:#}")] {
        assert!(!text.contains(secret), "error text leaks the token: {text}");
    }

    // Invalid file whose content looks like a secret.
    std::fs::write(&path, format!("{secret} extra\n")).unwrap();
    let r = call(&backend).await;
    assert!(is_refused(&r));
    // Missing file.
    std::fs::remove_file(&path).unwrap();
    let r = call(&backend).await;
    assert!(is_refused(&r));

    assert!(!logs_contain(secret), "the token appeared in a log line");
}

// ---- Final fix round (F1, K8 audit hardening) --------------------------------------
//
// Pinned behaviour of `read_token`:
// - it opens the file with `O_NONBLOCK` and reads it only when the open descriptor is a
//   regular file (`fstat`), so a FIFO, a socket or a device at the path never blocks a
//   call: no header, as for any invalid file. A symlink to a regular file is still read.
// - an invalid file (bad content, not a regular file) logs a WARN naming the path, never
//   the content, rate-limited: repeated invalid reads log it once (within a minute).

/// A FIFO (nobody writes to it) at the token path: the call still goes out at once,
/// without a header. Without `O_NONBLOCK` the open blocks a pool thread forever.
#[tokio::test]
async fn a_fifo_at_the_token_path_never_blocks_a_call() {
    let fake = FakeComputeCtl::start(SECRET).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    let made = std::process::Command::new("mkfifo")
        .arg(path.as_str())
        .status()
        .unwrap();
    assert!(made.success(), "mkfifo failed");
    let backend = fake.backend(Some(path.clone()));

    let Ok(r) = tokio::time::timeout(std::time::Duration::from_secs(10), call(&backend)).await
    else {
        // Let the blocked open finish, so the runtime can shut down after the failure.
        let fifo = path.clone();
        std::thread::spawn(move || drop(std::fs::OpenOptions::new().write(true).open(fifo)));
        panic!("a FIFO at the token path blocked the compute_ctl call");
    };
    assert!(is_refused(&r), "a FIFO: expected a 401, got {r:?}");
    assert_eq!(fake.requests(), vec![Vec::<String>::new()], "no header");

    // A regular file in its place works again.
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, format!("{SECRET}\n")).unwrap();
    call(&backend).await.unwrap();
}

/// compute_ctl never makes the token file a symlink, but one to a regular file is
/// read like the file (as the neon extension's reader does).
#[tokio::test]
async fn a_symlink_to_a_regular_file_is_read() {
    let fake = FakeComputeCtl::start(SECRET).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let target = dir.path().join("real.token");
    std::fs::write(&target, format!("{SECRET}\n")).unwrap();
    let path = token_path(&dir);
    std::os::unix::fs::symlink(&target, &path).unwrap();
    call(&fake.backend(Some(path))).await.unwrap();
    assert_eq!(fake.requests(), vec![vec![format!("Bearer {SECRET}")]]);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn an_invalid_token_file_warns_once_without_its_content() {
    let fake = FakeComputeCtl::start(SECRET).await;
    let dir = camino_tempfile::tempdir().unwrap();
    let path = token_path(&dir);
    std::fs::write(&path, "f1BadTokenNeedle has spaces\n").unwrap();
    let backend = fake.backend(Some(path.clone()));

    for i in 0..5 {
        assert_no_header_and_refused(&fake, &backend, &format!("invalid, call {i}")).await;
    }
    let wanted = path.to_string();
    logs_assert(|lines: &[&str]| {
        let warnings = lines
            .iter()
            .filter(|l| l.contains("WARN") && l.contains(&wanted))
            .count();
        if warnings == 1 {
            Ok(())
        } else {
            Err(format!(
                "{warnings} WARN lines naming {wanted} for 5 invalid reads (want exactly 1)"
            ))
        }
    });
    assert!(
        !logs_contain("f1BadTokenNeedle"),
        "the invalid file's content appeared in a log line"
    );

    // A valid file logs no warning.
    std::fs::write(&path, format!("{SECRET}\n")).unwrap();
    call(&backend).await.unwrap();
    assert!(!logs_contain(SECRET), "the token appeared in a log line");
}
