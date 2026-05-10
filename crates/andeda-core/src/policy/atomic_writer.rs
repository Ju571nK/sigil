//! Crash-safe writer for policy.yaml + last_applied_policy_version.
//!
//! Spec §4.4. The on-disk + state.db tuple must be advanced atomically (or
//! recoverably) even across abrupt power loss between the two writes.

use crate::state::{HashCache, StateError};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors produced by the atomic writer.
#[derive(Debug, Error)]
pub enum AtomicWriteError {
    /// I/O failure during write/rename/fsync.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// state.db update failure after disk write succeeded — caller should
    /// log loudly; the disk file is ahead of state.db, but boot reconciliation
    /// in `reconcile_on_boot` will recover.
    #[error("state.db update failed AFTER disk write: {0}")]
    StateAfterDisk(StateError),
}

/// Atomically write `policy_bytes` to `target` and advance `last_applied_policy_version`
/// to `new_version`. Steps:
///   1. Write `policy_bytes` to `target.{pid}.tmp`, fsync the file.
///   2. Rename temp → target.
///   3. fsync the parent directory.
///   4. UPDATE host_meta SET last_applied_policy_version = new_version.
///
/// A crash between steps 3 and 4 leaves disk ahead of state.db; the boot
/// reconciliation step (Task A6.5) detects this and re-emits the
/// `policy_reloaded` event.
pub fn atomic_write(
    target: &Path,
    policy_bytes: &[u8],
    cache: &HashCache,
    new_version: i64,
) -> Result<(), AtomicWriteError> {
    let parent = target
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent)?;

    let pid = std::process::id();
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("policy.yaml"),
        pid
    ));

    // 1. Write + fsync the file.
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(policy_bytes)?;
        f.sync_all()?;
    }

    // 2. Rename atomically.
    std::fs::rename(&tmp, target)?;

    // 3. fsync parent directory (POSIX only — no-op on Windows where
    //    rename's durability semantics differ).
    #[cfg(unix)]
    {
        let dir = std::fs::OpenOptions::new().read(true).open(&parent)?;
        dir.sync_all()?;
    }

    // 4. Advance state.db. If THIS step fails, disk is ahead; boot
    //    reconciliation handles it. We surface the error so the caller can
    //    log it for operator triage.
    cache
        .host_meta_set_policy_version(new_version)
        .map_err(AtomicWriteError::StateAfterDisk)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_cache(dir: &tempfile::TempDir) -> HashCache {
        HashCache::open(&dir.path().join("state.db")).unwrap()
    }

    #[test]
    fn writes_policy_and_advances_version() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("policy.yaml");
        atomic_write(&target, b"version: 5\nrules: []\n", &cache, 5).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"version: 5\nrules: []\n");
        assert_eq!(
            cache.host_meta_get().unwrap().last_applied_policy_version,
            5
        );
    }

    #[test]
    fn second_write_overwrites_atomically() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("policy.yaml");
        atomic_write(&target, b"version: 1\n", &cache, 1).unwrap();
        atomic_write(&target, b"version: 2\n", &cache, 2).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"version: 2\n");
        assert_eq!(
            cache.host_meta_get().unwrap().last_applied_policy_version,
            2
        );
    }

    #[test]
    fn temp_file_is_cleaned_after_rename() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("policy.yaml");
        atomic_write(&target, b"x", &cache, 1).unwrap();

        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftover.is_empty(),
            "no .tmp files should remain after successful rename"
        );
    }

    #[test]
    fn creates_parent_directory_if_missing() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("nested/sub/policy.yaml");
        atomic_write(&target, b"version: 1\n", &cache, 1).unwrap();
        assert!(target.exists());
    }
}
