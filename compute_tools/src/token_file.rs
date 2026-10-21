//! compute_ctl's token files (spec §4.1, writer side).
//!
//! compute_ctl hands two secrets to the processes on the compute through files
//! outside pgdata, never through the environment, a setting or a log line:
//! - the internal API secret (`compute_ctl_internal.token`), drawn at every
//!   start; every caller of the internal server sends it as a bearer;
//! - the tenant storage token (`storage_auth.token`), the password of every
//!   pageserver and safekeeper connection, replaced on refresh.
//!
//! Each file holds one line (`<token>\n`), mode 0600, owned by compute_ctl's
//! user, and is replaced atomically: written to `<file>.tmp.<pid>` (created
//! exclusively), `fsync`ed, renamed over the file, then the directory is
//! `fsync`ed. A reader opens either the old or the new inode, both whole.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use tracing::warn;

/// The file name of the internal API secret, in pgdata's parent by default.
pub const INTERNAL_API_TOKEN_FILE: &str = "compute_ctl_internal.token";

/// The file name of the tenant storage token, in pgdata's parent by default.
pub const STORAGE_AUTH_TOKEN_FILE: &str = "storage_auth.token";

/// The longest token the neon extension's reader accepts (its whole file is at
/// most 8 KiB, the line included).
pub const MAX_TOKEN_LEN: usize = 8191;

/// The default path of a token file: `file_name` in pgdata's parent, never
/// inside pgdata (a trailing `/` on `pgdata` doesn't matter).
pub fn default_token_path(pgdata: &Path, file_name: &str) -> PathBuf {
    match pgdata.parent() {
        Some(parent) => parent.join(file_name),
        // pgdata is `/` (or empty): there is no parent to put it in.
        None => Path::new("/").join(file_name),
    }
}

/// Whether `token` is what the neon extension's reader accepts: one line of
/// `[A-Za-z0-9._~+/=-]`, 1–8191 bytes (without the newline the writer adds).
pub fn is_valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b))
}

/// Writes `token` to `path` atomically (see the module docs). A token that
/// [`is_valid_token`] refuses is an error and nothing is written. On any error
/// before the rename, the old file is left as it was and the temporary file is
/// removed. The token never reaches an error message or the log.
pub fn write_token_file(path: &Path, token: &str) -> Result<()> {
    if !is_valid_token(token) {
        bail!(
            "refusing to write {}: not a valid token (one line of [A-Za-z0-9._~+/=-], 1-{MAX_TOKEN_LEN} bytes)",
            path.display()
        );
    }
    let file_name = path
        .file_name()
        .with_context(|| format!("token file path {} has no file name", path.display()))?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let tmp = dir.join(format!(
        "{}.tmp.{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    // A temporary file of this very name is what a crash of an earlier
    // compute_ctl with the same pid left behind: never trust it.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("remove stale {}", tmp.display()));
        }
    }

    if let Err(e) = write_new_file(&tmp, token) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename {} over {}", tmp.display(), path.display()));
    }
    // The new file is in place; a failed directory fsync only weakens its
    // durability across a host crash, so it is logged, not returned.
    if let Err(e) = File::open(&dir).and_then(|d| d.sync_all()) {
        warn!(
            "fsync of {} after replacing a token file: {e}",
            dir.display()
        );
    }
    Ok(())
}

/// Creates `tmp` exclusively with mode 0600 and writes `<token>\n` to it, synced.
fn write_new_file(tmp: &Path, token: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    let mut content = Vec::with_capacity(token.len() + 1);
    content.extend_from_slice(token.as_bytes());
    content.push(b'\n');
    file.write_all(&content)
        .with_context(|| format!("write {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync {}", tmp.display()))?;
    Ok(())
}

/// Removes a token file left by an earlier start (a missing file is fine).
pub fn remove_token_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

/// A fresh internal API secret: 32 bytes from the OS RNG, lowercase hex.
pub fn generate_internal_api_secret() -> String {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the OS random number generator failed");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compares a presented secret with the expected one in time independent of
/// where they differ (a length difference is not secret: every secret is 64
/// characters).
pub fn secrets_match(presented: &[u8], expected: &[u8]) -> bool {
    if presented.len() != expected.len() {
        return false;
    }
    aws_lc_rs::constant_time::verify_slices_are_equal(presented, expected).is_ok()
}
