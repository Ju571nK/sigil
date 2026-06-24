//! #184 — cross-process advisory file lock (flock) for the token store.
//!
//! The token file is read-modify-written by BOTH the CLI `issue()` (separate
//! process) and the server `check`/`mark_used` paths. A `Mutex` only serializes
//! within one process; flock(2) is what serializes across processes so
//! single-use can't be broken by a CLI append racing a server redeem.
//!
//! We lock a sidecar `<tokens>.lock` file (never the data file itself) so the
//! atomic tmp+rename of the data file can't swap the inode out from under a held
//! lock. The guard releases on Drop (or process exit / fd close).

use std::path::{Path, PathBuf};

/// Held advisory lock. Releases (flock LOCK_UN happens implicitly on close) when
/// dropped. On non-unix this is a no-op guard (best-effort; reference target is
/// unix). The held `File` keeps the fd open for the lock's lifetime.
pub struct FileLock {
    #[cfg(unix)]
    _file: std::fs::File,
}

impl FileLock {
    /// Acquire an exclusive advisory lock on `<path>.lock`, creating it 0600.
    /// Blocks until the lock is available.
    pub fn acquire_exclusive(data_path: &Path) -> std::io::Result<FileLock> {
        let lock_path = lock_path_for(data_path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::io::AsRawFd;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(&lock_path)?;
            // SAFETY: flock(2) with a valid fd from the File we own; the fd
            // outlives the call. LOCK_EX blocks until acquired.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(FileLock { _file: file })
        }
        #[cfg(not(unix))]
        {
            // Best-effort: ensure the lock file exists, but no real locking.
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&lock_path)?;
            Ok(FileLock {})
        }
    }
}

fn lock_path_for(data_path: &Path) -> PathBuf {
    let mut s = data_path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}
