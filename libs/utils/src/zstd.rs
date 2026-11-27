use std::io::SeekFrom;

use anyhow::{Context, Result};
use async_compression::Level;
use async_compression::tokio::bufread::ZstdDecoder;
use async_compression::tokio::write::ZstdEncoder;
use async_compression::zstd::CParameter;
use camino::Utf8Path;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufRead, AsyncSeekExt, AsyncWriteExt};
use tokio_tar::{Archive, Builder, HeaderMode};
use walkdir::WalkDir;

/// Creates a Zstandard tarball.
pub async fn create_zst_tarball(path: &Utf8Path, tarball: &Utf8Path) -> Result<(File, u64)> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&tarball)
        .await
        .with_context(|| format!("tempfile creation {tarball}"))?;

    let mut paths = Vec::new();
    for entry in WalkDir::new(path) {
        let entry = entry?;
        let metadata = entry.metadata().expect("error getting dir entry metadata");
        // Also allow directories so that we also get empty directories
        if !(metadata.is_file() || metadata.is_dir()) {
            continue;
        }
        let path = entry.into_path();
        paths.push(path);
    }
    // Do a sort to get a more consistent listing
    paths.sort_unstable();
    let zstd = ZstdEncoder::with_quality_and_params(
        file,
        Level::Default,
        &[CParameter::enable_long_distance_matching(true)],
    );
    let mut builder = Builder::new(zstd);
    // Use reproducible header mode
    builder.mode(HeaderMode::Deterministic);
    for p in paths {
        let rel_path = p.strip_prefix(path)?;
        if rel_path.is_empty() {
            // The top directory should not be compressed,
            // the tar crate doesn't like that
            continue;
        }
        builder.append_path_with_name(&p, rel_path).await?;
    }
    let mut zstd = builder.into_inner().await?;
    zstd.shutdown().await?;
    let mut compressed = zstd.into_inner();
    let compressed_len = compressed.metadata().await?.len();
    compressed.seek(SeekFrom::Start(0)).await?;
    Ok((compressed, compressed_len))
}

/// Creates a Zstandard tarball.
pub async fn extract_zst_tarball(
    path: &Utf8Path,
    tarball: impl AsyncBufRead + Unpin,
) -> Result<()> {
    let decoder = Box::pin(ZstdDecoder::new(tarball));
    let mut archive = Archive::new(decoder);
    archive.unpack(path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use camino_tempfile::tempdir;
    use tokio::io::BufReader;

    use super::*;

    /// A tarball made by `create_zst_tarball` unpacks to the same tree: nested
    /// directories, an empty directory, and files under, at and over 8 KiB (the
    /// copy buffer size and more than one 512-byte tar block).
    #[tokio::test]
    async fn a_tarball_round_trips_nested_directories_and_large_files() {
        let src = tempdir().unwrap();
        let files: [(&str, usize); 4] = [
            ("top.txt", 5),
            ("a/b/exact_8k", 8192),
            ("a/b/c/over_8k", 8192 * 3 + 17),
            ("a/two_blocks", 513),
        ];
        for (path, len) in files {
            let full = src.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            std::fs::write(&full, content).unwrap();
        }
        std::fs::create_dir_all(src.path().join("a/empty")).unwrap();

        let out = tempdir().unwrap();
        let tarball = out.path().join("t.tar.zst");
        let (file, len) = create_zst_tarball(src.path(), &tarball).await.unwrap();
        assert!(len > 0);

        let dst = out.path().join("unpacked");
        std::fs::create_dir(&dst).unwrap();
        extract_zst_tarball(&dst, BufReader::new(file)).await.unwrap();

        for (path, len) in files {
            let got = std::fs::read(dst.join(path)).unwrap();
            let want: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(got, want, "{path}");
        }
        assert!(dst.join("a/empty").is_dir());
    }
}
