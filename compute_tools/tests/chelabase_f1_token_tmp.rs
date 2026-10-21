//! Fork round 4, final fix round (lane F1, item 2, K3 audit): stale token temp
//! files.
//!
//! Pinned interface (the code under test):
//! - `token_file::remove_stale_temp_files(path: &Path) -> anyhow::Result<()>`:
//!   removes every directory entry named `<file name of path>.tmp.<anything>`
//!   next to `path` (whatever pid wrote it; a symlink is removed itself, never
//!   its target), and nothing else; a missing directory is `Ok`. compute_ctl
//!   calls it at start for both token files, before it writes either.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use compute_tools::token_file::{
    INTERNAL_API_TOKEN_FILE, STORAGE_AUTH_TOKEN_FILE, remove_stale_temp_files,
};

fn fresh(name: &str) -> PathBuf {
    let dir = Path::new("./tests/tmp").join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(&dir).unwrap()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

/// A crash between the exclusive create and the rename leaves
/// `<name>.tmp.<pid>` behind, under whatever pid that compute_ctl had: every
/// one of them goes at start, and nothing else does.
#[test]
fn every_stale_temp_file_of_a_token_file_is_removed() {
    let dir = fresh("f1_tmp_sweep");
    let storage = dir.join(STORAGE_AUTH_TOKEN_FILE);
    let internal = dir.join(INTERNAL_API_TOKEN_FILE);
    fs::write(&storage, "current\n").unwrap();
    fs::write(&internal, "current\n").unwrap();

    let stale = [
        "storage_auth.token.tmp.1",
        "storage_auth.token.tmp.4194304",
        "storage_auth.token.tmp.x.y",
    ];
    for name in stale {
        fs::write(dir.join(name), "stale\n").unwrap();
    }
    // A stale entry that is a symlink goes itself; its target stays.
    let victim_dir = dir.join("keep");
    fs::create_dir(&victim_dir).unwrap();
    let victim = victim_dir.join("victim");
    fs::write(&victim, "victim\n").unwrap();
    symlink(&victim, dir.join("storage_auth.token.tmp.77")).unwrap();

    let kept = [
        "storage_auth.token",
        "storage_auth.token.tmp",
        "storage_auth.token.bak",
        "storage_auth.tokenx.tmp.1",
        "xstorage_auth.token.tmp.1",
        "compute_ctl_internal.token.tmp.7",
    ];
    for name in &kept[1..] {
        fs::write(dir.join(name), "kept\n").unwrap();
    }

    remove_stale_temp_files(&storage).unwrap();
    for name in stale.iter().chain(["storage_auth.token.tmp.77"].iter()) {
        assert!(
            fs::symlink_metadata(dir.join(name)).is_err(),
            "{name} must be removed"
        );
    }
    assert_eq!(
        read(&victim),
        "victim\n",
        "a symlink's target is never touched"
    );
    for name in kept {
        assert!(dir.join(name).exists(), "{name} must be kept");
    }
    assert_eq!(read(&storage), "current\n");

    remove_stale_temp_files(&internal).unwrap();
    assert!(!dir.join("compute_ctl_internal.token.tmp.7").exists());
    assert_eq!(read(&internal), "current\n");
    assert!(dir.join("storage_auth.token.tmp").exists());

    // Nothing to remove, or no directory yet: not an error.
    remove_stale_temp_files(&storage).unwrap();
    remove_stale_temp_files(&dir.join("absent").join(STORAGE_AUTH_TOKEN_FILE)).unwrap();
    fs::remove_dir_all(&dir).unwrap();
}
