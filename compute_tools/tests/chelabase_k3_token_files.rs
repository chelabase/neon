//! Fork round 4, K3: compute_ctl's token-file writer (spec §4.1 writer side,
//! U1, RT4-10; plan "Shared interfaces (pinned)", token files).
//!
//! Pinned interfaces (the code under test), module `compute_tools::token_file`:
//! - `pub const INTERNAL_API_TOKEN_FILE: &str = "compute_ctl_internal.token"` and
//!   `pub const STORAGE_AUTH_TOKEN_FILE: &str = "storage_auth.token"`: the file
//!   names of the two defaults.
//! - `pub fn default_token_path(pgdata: &Path, file_name: &str) -> PathBuf`: the
//!   file in pgdata's parent (never inside pgdata), what `--internal-api-token-file`
//!   and `--storage-auth-token-file` default to.
//! - `pub fn is_valid_token(token: &str) -> bool`: the reader's alphabet, one line
//!   of `[A-Za-z0-9._~+/=-]`, 1–8191 bytes (no newline: the writer adds it).
//! - `pub fn write_token_file(path: &Path, token: &str) -> anyhow::Result<()>`:
//!   refuses a token `is_valid_token` refuses (nothing written); otherwise writes
//!   `<token>\n` to `<path>.tmp.<pid>` (created `O_CREAT|O_EXCL`, mode 0600; a
//!   stale temp of that name from a crash is removed first), `fsync`s it, renames
//!   it over `<path>` and `fsync`s the directory. On any failure the old file is
//!   left as it was and the temp is removed. Never logs the token.
//! - `pub fn generate_internal_api_secret() -> String`: 32 bytes from the OS RNG,
//!   lowercase hex (64 characters).

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use compute_tools::token_file::{
    INTERNAL_API_TOKEN_FILE, STORAGE_AUTH_TOKEN_FILE, default_token_path,
    generate_internal_api_secret, is_valid_token, write_token_file,
};

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

/// This process's effective uid (the owner of `/proc/self`).
fn euid() -> u32 {
    fs::metadata("/proc/self").unwrap().uid()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn temps(dir: &Path, file_name: &str) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&format!("{file_name}.tmp.")))
        .collect()
}

/// Everything `tracing` prints while `f` runs on this thread.
fn captured_logs(f: impl FnOnce()) -> String {
    #[derive(Clone)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf(Arc::new(Mutex::new(Vec::new())));
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
}

#[test]
fn the_files_default_to_pgdatas_parent() {
    assert_eq!(INTERNAL_API_TOKEN_FILE, "compute_ctl_internal.token");
    assert_eq!(STORAGE_AUTH_TOKEN_FILE, "storage_auth.token");
    for pgdata in ["/var/db/postgres/compute", "/var/db/postgres/compute/"] {
        let pgdata = Path::new(pgdata);
        let internal = default_token_path(pgdata, INTERNAL_API_TOKEN_FILE);
        let storage = default_token_path(pgdata, STORAGE_AUTH_TOKEN_FILE);
        assert_eq!(
            internal,
            Path::new("/var/db/postgres/compute_ctl_internal.token")
        );
        assert_eq!(storage, Path::new("/var/db/postgres/storage_auth.token"));
        assert!(!internal.starts_with(pgdata) && !storage.starts_with(pgdata));
    }
    // neon_local: <endpoint dir>/pgdata -> <endpoint dir>/compute_ctl_internal.token
    assert_eq!(
        default_token_path(
            Path::new("/repo/endpoints/ep-1/pgdata"),
            INTERNAL_API_TOKEN_FILE
        ),
        Path::new("/repo/endpoints/ep-1/compute_ctl_internal.token")
    );
}

#[test]
fn the_token_alphabet_is_the_readers() {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/=-";
    for ok in ["a", "eyJhbGciOiJFZERTQSJ9.eyJzIjoxfQ.c2ln", alphabet] {
        assert!(is_valid_token(ok), "{ok:?} is a token");
    }
    assert!(is_valid_token(&"a".repeat(8191)), "8191 bytes is the limit");
    assert!(!is_valid_token(&"a".repeat(8192)), "8192 bytes is too long");
    for bad in [
        "", " ", "a b", "a\n", "\na", "a\nb", "a\r", "a\tb", "a\0b", "é", "a,b", "a;b", "a:b",
        "a'b", "a\"b", "a\\b", "a%b", "a#b", "a@b", "a*b", "a(b", "a$b",
    ] {
        assert!(!is_valid_token(bad), "{bad:?} is not a token");
    }
}

#[test]
fn a_new_file_is_0600_owned_by_us_with_one_line() {
    let dir = fresh("k3_token_new");
    let path = dir.join(STORAGE_AUTH_TOKEN_FILE);
    write_token_file(&path, "tok.en-1").unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "tok.en-1\n");
    let meta = fs::metadata(&path).unwrap();
    assert!(meta.is_file());
    assert_eq!(mode(&path), 0o600);
    assert_eq!(meta.uid(), euid(), "owned by compute_ctl's user");
    assert!(
        temps(&dir, STORAGE_AUTH_TOKEN_FILE).is_empty(),
        "no temp left"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_rewrite_replaces_the_file_by_rename() {
    let dir = fresh("k3_token_replace");
    let path = dir.join(INTERNAL_API_TOKEN_FILE);
    fs::write(&path, "old\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let old_inode = fs::metadata(&path).unwrap().ino();
    let mut reader = fs::File::open(&path).unwrap();

    write_token_file(&path, "new").unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    assert_eq!(
        mode(&path),
        0o600,
        "the new file is 0600 whatever the old one was"
    );
    assert_ne!(
        fs::metadata(&path).unwrap().ino(),
        old_inode,
        "a new inode (rename)"
    );
    // A reader that opened the old file still reads it whole: never truncated.
    let mut seen = String::new();
    reader.read_to_string(&mut seen).unwrap();
    assert_eq!(seen, "old\n");
    assert!(temps(&dir, INTERNAL_API_TOKEN_FILE).is_empty());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_stale_temp_from_a_crash_is_replaced() {
    let dir = fresh("k3_token_stale_temp");
    let path = dir.join(STORAGE_AUTH_TOKEN_FILE);
    fs::write(&path, "old\n").unwrap();
    // What a crash between the temp write and the rename leaves, under the very
    // name this process would use.
    let stale = dir.join(format!(
        "{STORAGE_AUTH_TOKEN_FILE}.tmp.{}",
        std::process::id()
    ));
    fs::write(&stale, "half-writ").unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o644)).unwrap();

    write_token_file(&path, "fresh").unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), "fresh\n");
    assert_eq!(mode(&path), 0o600);
    assert!(!stale.exists(), "the stale temp is gone");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_write_keeps_the_old_file() {
    let dir = fresh("k3_token_failure");

    // The rename can't replace a directory: an error, the directory untouched,
    // no temp left behind.
    let blocked = dir.join("blocked.token");
    fs::create_dir(&blocked).unwrap();
    assert!(write_token_file(&blocked, "tok").is_err());
    assert!(blocked.is_dir());
    assert!(
        temps(&dir, "blocked.token").is_empty(),
        "the temp is removed on failure"
    );

    // An invalid token is refused before anything is written.
    let path = dir.join(STORAGE_AUTH_TOKEN_FILE);
    fs::write(&path, "old\n").unwrap();
    for bad in ["", "two\nlines", "sp ace"] {
        assert!(write_token_file(&path, bad).is_err(), "{bad:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "old\n", "{bad:?}");
    }
    assert!(temps(&dir, STORAGE_AUTH_TOKEN_FILE).is_empty());

    // A directory the temp can't be created in (skipped as root, who can write
    // anywhere; ci-local runs the tests as uid 1000).
    if euid() != 0 {
        let ro = dir.join("ro");
        fs::create_dir(&ro).unwrap();
        let path = ro.join(STORAGE_AUTH_TOKEN_FILE);
        fs::write(&path, "old\n").unwrap();
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o500)).unwrap();
        let result = write_token_file(&path, "new");
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "old\n");
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn writing_never_logs_the_token() {
    let dir = fresh("k3_token_logs");
    let path = dir.join(STORAGE_AUTH_TOKEN_FILE);
    let blocked = dir.join("blocked.token");
    fs::create_dir(&blocked).unwrap();
    let logs = captured_logs(|| {
        write_token_file(&path, "k3logneedle.ok").unwrap();
        let _ = write_token_file(&blocked, "k3logneedle.failed");
        let _ = write_token_file(&path, "k3logneedle invalid");
    });
    assert!(
        !logs.contains("k3logneedle"),
        "a token reached the log:\n{logs}"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_internal_secret_is_64_hex_from_the_rng() {
    let a = generate_internal_api_secret();
    let b = generate_internal_api_secret();
    for s in [&a, &b] {
        assert_eq!(s.len(), 64, "{s}");
        assert!(
            s.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "lowercase hex: {s}"
        );
        assert!(is_valid_token(s));
    }
    assert_ne!(a, b, "a fresh secret each time");
}
