//! Reading a secret (a token, a password) from a file named by a command-line flag, so the
//! secret never has to sit in a process's environment or on its command line.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use anyhow::bail;
use camino::Utf8Path;

/// The longest secret file [`read_secret_file`] reads.
pub const MAX_SECRET_FILE_LEN: u64 = 64 * 1024;

/// The secret in the file `path` given by `flag`: its content with one trailing `\n`
/// trimmed, read once. The open is `O_NONBLOCK` and only a regular file is read (a symlink
/// to one is followed), so a FIFO at the path never blocks the caller. An unreadable,
/// missing, non-regular, oversized, non-UTF-8 or empty file, or a control character
/// (`char::is_control`, a second newline or a `\r` included) in the secret, is an error
/// naming `flag` and the path, never the content.
pub fn read_secret_file(path: &Utf8Path, flag: &str) -> anyhow::Result<String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| anyhow::anyhow!("cannot read {flag} {path}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| anyhow::anyhow!("cannot read {flag} {path}: {e}"))?;
    if !meta.file_type().is_file() {
        bail!("{flag} {path} is not a regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_SECRET_FILE_LEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow::anyhow!("cannot read {flag} {path}: {e}"))?;
    if bytes.len() as u64 > MAX_SECRET_FILE_LEN {
        bail!("{flag} {path} is larger than {MAX_SECRET_FILE_LEN} bytes");
    }
    let content =
        String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("{flag} {path} is not UTF-8"))?;
    let secret = content.strip_suffix('\n').unwrap_or(&content);
    if secret.is_empty() {
        bail!("{flag} {path} is empty");
    }
    if secret.chars().any(char::is_control) {
        bail!("{flag} {path} holds a control character (one line, one optional trailing newline)");
    }
    Ok(secret.to_owned())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::read_secret_file;

    const FLAG: &str = "--edge-secret-file";

    /// A symlink to a FIFO is refused at once (the open is non-blocking, the type check
    /// follows the link), as are a dangling symlink and a symlink to a directory.
    #[test]
    fn symlinks_to_non_regular_files_fail_at_once() {
        let dir = camino_tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(fifo.as_str())
            .status()
            .unwrap();
        assert!(made.success(), "mkfifo failed");
        let to_fifo = dir.path().join("to-fifo");
        std::os::unix::fs::symlink(&fifo, &to_fifo).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let path = to_fifo.clone();
        std::thread::spawn(move || drop(tx.send(read_secret_file(&path, FLAG).map(|_| ()))));
        let Ok(r) = rx.recv_timeout(Duration::from_secs(10)) else {
            std::thread::spawn(move || drop(std::fs::OpenOptions::new().write(true).open(fifo)));
            panic!("a symlink to a FIFO blocked");
        };
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains(FLAG) && e.contains("regular file"), "{e}");

        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        let e = format!("{:#}", read_secret_file(&dangling, FLAG).unwrap_err());
        assert!(e.contains(FLAG) && e.contains(dangling.as_str()), "{e}");

        let to_dir = dir.path().join("to-dir");
        std::os::unix::fs::symlink(dir.path(), &to_dir).unwrap();
        let e = format!("{:#}", read_secret_file(&to_dir, FLAG).unwrap_err());
        assert!(e.contains(FLAG), "{e}");
    }

    /// A secret of a single character is read, with or without its newline.
    #[test]
    fn the_smallest_secret_is_read() {
        let dir = camino_tempfile::tempdir().unwrap();
        let file = dir.path().join("s");
        for content in ["x\n", "x"] {
            std::fs::write(&file, content).unwrap();
            assert_eq!(read_secret_file(&file, FLAG).unwrap(), "x", "{content:?}");
        }
    }

    /// The cap applies to the file, the trailing newline included.
    #[test]
    fn the_cap_counts_the_trailing_newline() {
        let dir = camino_tempfile::tempdir().unwrap();
        let file = dir.path().join("s");
        let mut content = vec![b'a'; 64 * 1024];
        content.push(b'\n');
        std::fs::write(&file, &content).unwrap();
        let e = format!("{:#}", read_secret_file(&file, FLAG).unwrap_err());
        assert!(e.contains("larger than"), "{e}");
    }
}
