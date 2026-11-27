//! Tar archives over async I/O, on the `tokio_tar` crate (async-tar).
//!
//! Two differences from using the crate directly:
//!
//! - [`Builder`] can be dropped unfinished. `tokio_tar::Builder` panics when dropped
//!   before `finish`, which an error return or a cancelled future does. Dropped
//!   unfinished, this one writes nothing more: the archive has no end-of-archive
//!   marker, so a reader sees it as truncated.
//! - [`entries`] fails when its input ends before the end-of-archive marker, where
//!   `tokio_tar::Archive::entries` ends quietly. A cut archive is an error, never a
//!   shorter archive.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use futures::{FutureExt, Stream};
use sync_wrapper::SyncWrapper;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub use tokio_tar::{EntryType, Header, HeaderMode};

/// Writes a tar archive into `W`. See the module documentation.
pub struct Builder<W: AsyncWrite + Unpin + Send> {
    /// `None` only once `into_inner` has taken it.
    inner: Option<tokio_tar::Builder<Sink<W>>>,
}

/// The builder's writer: `W`, made `Sync` (async-tar needs it; the builder only
/// ever uses it through `&mut`), and closed when the builder is dropped unfinished.
struct Sink<W> {
    inner: SyncWrapper<W>,
    closed: bool,
}

impl<W: AsyncWrite + Unpin> Sink<W> {
    fn check_open(&self) -> io::Result<()> {
        if self.closed {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tar builder dropped unfinished",
            ))
        } else {
            Ok(())
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Sink<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_open()?;
        Pin::new(this.inner.get_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_open()?;
        Pin::new(this.inner.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_open()?;
        Pin::new(this.inner.get_mut()).poll_shutdown(cx)
    }
}

impl<W: AsyncWrite + Unpin + Send> Builder<W> {
    /// A builder writing into `obj`, with `HeaderMode::Complete`.
    pub fn new(obj: W) -> Self {
        let sink = Sink {
            inner: SyncWrapper::new(obj),
            closed: false,
        };
        Builder {
            inner: Some(tokio_tar::Builder::new(sink)),
        }
    }

    fn builder(&mut self) -> &mut tokio_tar::Builder<Sink<W>> {
        self.inner.as_mut().expect("only into_inner takes the builder")
    }

    /// The header mode for entries read from the filesystem.
    pub fn mode(&mut self, mode: HeaderMode) {
        self.builder().mode(mode)
    }

    /// Appends `header` and `data`; `header`'s size must be `data`'s length.
    pub async fn append<R: AsyncRead + Unpin + Send>(
        &mut self,
        header: &Header,
        data: R,
    ) -> io::Result<()> {
        self.builder().append(header, data).await
    }

    /// Appends `data` at `path`, setting `header`'s path and checksum.
    pub async fn append_data<P: AsRef<Path>, R: AsyncRead + Unpin + Send>(
        &mut self,
        header: &mut Header,
        path: P,
        data: R,
    ) -> io::Result<()> {
        self.builder().append_data(header, path, data).await
    }

    /// Appends `file` at `path`, with the file's metadata.
    pub async fn append_file<P: AsRef<Path>>(&mut self, path: P, file: &mut File) -> io::Result<()> {
        self.builder().append_file(path, file).await
    }

    /// Appends the file or directory at `path`, named `name` in the archive.
    pub async fn append_path_with_name<P: AsRef<Path>, N: AsRef<Path>>(
        &mut self,
        path: P,
        name: N,
    ) -> io::Result<()> {
        self.builder().append_path_with_name(path, name).await
    }

    /// Writes the end-of-archive marker. Later calls do nothing.
    pub async fn finish(&mut self) -> io::Result<()> {
        self.builder().finish().await
    }

    /// Finishes the archive and returns the writer.
    pub async fn into_inner(mut self) -> io::Result<W> {
        // Finish while `self` still owns the builder: if this future is dropped
        // here, `Drop` handles it.
        self.finish().await?;
        let builder = self.inner.take().expect("only into_inner takes the builder");
        // Finished, so this writes nothing and completes at once.
        let sink = builder.into_inner().await?;
        Ok(sink.inner.into_inner())
    }
}

impl<W: AsyncWrite + Unpin + Send> Drop for Builder<W> {
    fn drop(&mut self) {
        if let Some(builder) = self.inner.as_mut() {
            // Close the writer, then let `finish` mark the builder finished: its
            // marker write fails at once on the closed writer, so nothing is
            // written and the inner builder's drop doesn't panic. (A finished
            // builder's `finish` does nothing.)
            builder.get_mut().closed = true;
            let _ = builder.finish().now_or_never();
        }
    }
}

/// The input of [`entries`]: records whether the archive's reader reached the end
/// of its input.
pub struct Input<R> {
    inner: R,
    eof: Arc<AtomicBool>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Input<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let wanted = buf.remaining() > 0;
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = res {
            if wanted && buf.filled().len() == before {
                this.eof.store(true, Ordering::Relaxed);
            }
        }
        res
    }
}

/// One member of an archive read with [`entries`].
pub type Entry<R> = tokio_tar::Entry<tokio_tar::Archive<Input<R>>>;

/// The members of a tar archive. See the module documentation.
pub struct Entries<R: AsyncRead + Unpin> {
    inner: tokio_tar::Entries<Input<R>>,
    eof: Arc<AtomicBool>,
    done: bool,
}

/// Reads the members of the tar archive in `reader`. The stream stops at the
/// end-of-archive marker, leaving the rest of `reader` unread; it fails if `reader`
/// ends first.
pub fn entries<R: AsyncRead + Unpin>(reader: R) -> io::Result<Entries<R>> {
    let eof = Arc::new(AtomicBool::new(false));
    let input = Input {
        inner: reader,
        eof: Arc::clone(&eof),
    };
    Ok(Entries {
        inner: tokio_tar::Archive::new(input).entries()?,
        eof,
        done: false,
    })
}

impl<R: AsyncRead + Unpin> Stream for Entries<R> {
    type Item = io::Result<Entry<R>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(None) => {
                this.done = true;
                // The archive stops at its first zero block without reading past it,
                // so reaching the end of the input means there was no marker.
                if this.eof.load(Ordering::Relaxed) {
                    Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tar archive ends before its end-of-archive marker",
                    ))))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Ready(Some(Err(e))) => {
                this.done = true;
                Poll::Ready(Some(Err(e)))
            }
            other => other,
        }
    }
}

/// The size of `entry`'s data, including a PAX `size` record's override of the
/// header's size field (the size the archive reader itself reads the data at).
pub async fn effective_size<R: AsyncRead + Unpin>(
    entry: &mut tokio_tar::Entry<R>,
) -> io::Result<u64> {
    if let Some(extensions) = entry.pax_extensions().await? {
        let mut size = None;
        for extension in extensions {
            let extension = extension?;
            if extension.key_bytes() == b"size" {
                let value = extension
                    .value()
                    .map_err(|_| io::Error::other("failed to parse pax size as string"))?;
                size = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| io::Error::other("failed to parse pax size"))?,
                );
            }
        }
        if let Some(size) = size {
            return Ok(size);
        }
    }
    entry.header().entry_size()
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio::io::AsyncReadExt;

    use super::*;

    fn header(len: usize) -> Header {
        let mut header = Header::new_gnu();
        header.set_size(len as u64);
        header
    }

    async fn archive(names: &[&str], finish: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut builder = Builder::new(&mut out);
        for name in names {
            let data = name.repeat(300);
            builder
                .append_data(&mut header(data.len()), name, data.as_bytes())
                .await
                .unwrap();
        }
        if finish {
            builder.into_inner().await.unwrap();
        } else {
            drop(builder);
        }
        out
    }

    async fn read_all(archive: &[u8]) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut entries = entries(archive)?;
        while let Some(entry) = entries.next().await {
            let mut entry = entry?;
            let path = entry.path()?.to_string_lossy().into_owned();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).await?;
            out.push((path, data));
        }
        Ok(out)
    }

    #[tokio::test]
    async fn a_finished_archive_round_trips() {
        let bytes = archive(&["a", "bb"], true).await;
        assert_eq!(&bytes[bytes.len() - 1024..], &[0u8; 1024][..]);
        let got = read_all(&bytes).await.unwrap();
        assert_eq!(
            got,
            vec![
                ("a".to_string(), "a".repeat(300).into_bytes()),
                ("bb".to_string(), "bb".repeat(300).into_bytes()),
            ]
        );
    }

    /// Dropped unfinished, the builder neither panics nor writes the marker.
    #[tokio::test]
    async fn a_builder_dropped_unfinished_writes_no_marker() {
        let finished = archive(&["a", "bb"], true).await;
        let unfinished = archive(&["a", "bb"], false).await;
        assert_eq!(unfinished, finished[..finished.len() - 1024]);
        let err = read_all(&unfinished).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// A writer that takes a few bytes, then stays pending forever.
    struct Stalls(Vec<u8>);

    impl AsyncWrite for Stalls {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.0.len() >= 700 {
                return Poll::Pending;
            }
            let n = buf.len().min(100);
            this.0.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A builder dropped in the middle of a write (a cancelled future) doesn't panic.
    #[tokio::test]
    async fn a_builder_dropped_mid_write_does_not_panic() {
        let mut builder = Builder::new(Stalls(Vec::new()));
        let data = vec![1u8; 5000];
        let mut header = header(data.len());
        let write = builder.append_data(&mut header, "f", data.as_slice());
        assert!(write.now_or_never().is_none(), "the write should stall");
        drop(builder);

        // And so does `into_inner` dropped while finishing.
        let mut builder = Builder::new(Stalls(vec![0; 650]));
        let _ = builder.append_data(&mut header, "f", &[][..]).now_or_never();
        assert!(builder.into_inner().now_or_never().is_none());
    }

    /// The reader stops at the marker and leaves what follows it unread.
    #[tokio::test]
    async fn entries_stop_at_the_marker() {
        let mut bytes = archive(&["a"], true).await;
        let len = bytes.len();
        bytes.extend_from_slice(b"after");
        let mut reader = bytes.as_slice();
        let mut entries = entries(&mut reader).unwrap();
        assert!(entries.next().await.unwrap().is_ok());
        assert!(entries.next().await.is_none());
        drop(entries);
        // The first zero block was read; the second one and the rest remain.
        assert_eq!(reader.len(), len + 5 - (len - 512));
        assert_eq!(&reader[512..], b"after");
    }

    /// Any cut before the marker is an error, wherever it falls.
    #[tokio::test]
    async fn a_cut_archive_is_an_error() {
        let bytes = archive(&["a", "bb"], true).await;
        for cut in 0..=bytes.len() - 1024 {
            let res = read_all(&bytes[..cut]).await;
            assert!(res.is_err(), "cut at {cut} of {} read as complete", bytes.len());
        }
    }

    /// A PAX `size` record overrides the header's size field.
    #[tokio::test]
    async fn effective_size_reads_a_pax_size() {
        let data = vec![3u8; 1500];
        let record = "13 size=1500\n";
        let mut out = Vec::new();
        let mut builder = Builder::new(&mut out);
        let mut pax = Header::new_ustar();
        pax.set_entry_type(EntryType::XHeader);
        pax.set_size(record.len() as u64);
        builder
            .append_data(&mut pax, "PaxHeaders/f", record.as_bytes())
            .await
            .unwrap();
        let mut file = Header::new_ustar();
        file.set_size(0);
        builder
            .append_data(&mut file, "f", data.as_slice())
            .await
            .unwrap();
        builder.into_inner().await.unwrap();

        let mut entries = entries(out.as_slice()).unwrap();
        let mut entry = entries.next().await.unwrap().unwrap();
        assert_eq!(entry.header().entry_size().unwrap(), 0);
        assert_eq!(effective_size(&mut entry).await.unwrap(), 1500);
        let mut got = Vec::new();
        entry.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data);
        drop(entry);
        assert!(entries.next().await.is_none());
    }
}
