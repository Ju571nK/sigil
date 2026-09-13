//! Stop accepting on shutdown, then give accepted requests a bounded drain.

use std::{future::Future, io, time::Duration};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub(crate) struct Connections(JoinSet<()>);

impl Connections {
    pub fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
        self.0.spawn(task);
    }

    pub async fn accept<T>(
        &mut self,
        accept: impl Future<Output = io::Result<T>>,
        shutdown: &CancellationToken,
    ) -> Option<io::Result<T>> {
        tokio::pin!(accept);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return None,
                done = self.0.join_next(), if !self.0.is_empty() => {
                    if let Some(Err(error)) = done {
                        return Some(Err(io::Error::other(error)));
                    }
                }
                result = &mut accept => return Some(result),
            }
        }
    }

    pub async fn drain(mut self) -> io::Result<()> {
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(done) = self.0.join_next().await {
                done.map_err(io::Error::other)?;
            }
            Ok(())
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.0.shutdown().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "IPC requests did not drain",
                ))
            }
        }
    }
}

#[cfg(unix)]
pub(crate) struct SocketFile {
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SocketFile {
    pub fn new(path: &std::path::Path) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[cfg(unix)]
impl Drop for SocketFile {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.dev() == self.device && m.ino() == self.inode)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_cleanup_preserves_a_replacement_listener() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("ipc.sock");
        let old = tokio::net::UnixListener::bind(&path).unwrap();
        let cleanup = SocketFile::new(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let new = tokio::net::UnixListener::bind(&path).unwrap();
        drop(cleanup);
        assert!(path.exists());
        let cleanup = SocketFile::new(&path).unwrap();
        drop(new);
        drop(cleanup);
        assert!(!path.exists());
        drop(old);
    }

    #[tokio::test]
    async fn cancellation_stops_accepting_but_drains_accepted_work() {
        let mut connections = Connections::default();
        let (tx, rx) = tokio::sync::oneshot::channel();
        connections.spawn(async move {
            tokio::task::yield_now().await;
            tx.send(42).unwrap();
        });
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        assert!(connections
            .accept(async { Ok(()) }, &shutdown)
            .await
            .is_none());
        connections.drain().await.unwrap();
        assert_eq!(rx.await.unwrap(), 42);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_peer_is_aborted_and_reported_as_incomplete_drain() {
        let mut connections = Connections::default();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        connections.spawn(async move {
            let _owned = tx;
            std::future::pending::<()>().await;
        });
        assert_eq!(
            connections.drain().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(rx.await.is_err());
    }
}
