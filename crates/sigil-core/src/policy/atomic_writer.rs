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
    // 1–3. Crash-safe file write (tmp + fsync + rename + dir fsync).
    write_file_durably(target, policy_bytes)?;

    // 4. Advance state.db. If THIS step fails, disk is ahead; boot
    //    reconciliation handles it. We surface the error so the caller can
    //    log it for operator triage.
    cache
        .host_meta_set_policy_version(new_version)
        .map_err(AtomicWriteError::StateAfterDisk)?;

    Ok(())
}

/// Sibling of [`atomic_write`] for a signed rule-packs bundle: the SAME
/// crash-safe file write, but it advances the RULE-PACKS watermark
/// (`last_applied_rule_packs_version`) instead of the policy version. Same
/// `AtomicWriteError` semantics: a crash between the disk write and the state.db
/// update leaves disk ahead, recovered by boot reconciliation.
pub fn atomic_write_rule_packs(
    target: &Path,
    rule_packs_bytes: &[u8],
    cache: &HashCache,
    new_version: i64,
) -> Result<(), AtomicWriteError> {
    // 1–3. Crash-safe file write (tmp + fsync + rename + dir fsync).
    write_file_durably(target, rule_packs_bytes)?;

    // 4. Advance the rule-packs watermark in state.db.
    cache
        .set_last_applied_rule_packs_version(new_version)
        .map_err(AtomicWriteError::StateAfterDisk)?;

    Ok(())
}

/// Shared crash-safe file write (steps 1–3 of the atomic-write protocol):
/// write `bytes` to a pid-scoped temp file, fsync it, rename it over `target`,
/// then fsync the parent directory (POSIX only). Does NOT touch state.db.
fn write_file_durably(target: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
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
        f.write_all(bytes)?;
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
    fn writes_rule_packs_and_advances_rule_packs_version() {
        let dir = tempdir().unwrap();
        let cache = fresh_cache(&dir);
        let target = dir.path().join("rule_packs.yaml");
        atomic_write_rule_packs(&target, b"version: 1\nrule_packs: []\n", &cache, 3).unwrap();

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"version: 1\nrule_packs: []\n"
        );
        assert_eq!(
            cache
                .host_meta_get()
                .unwrap()
                .last_applied_rule_packs_version,
            3
        );
        // The policy watermark is untouched by the rule-packs writer.
        assert_eq!(
            cache.host_meta_get().unwrap().last_applied_policy_version,
            0
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
