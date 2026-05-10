//! Sender offset state persisted to `sender-offset.json`.
//!
//! Spec §3.8.3 — `byte_offset` is a file position; `last_acked_sequence`
//! is the per-host monotonic event counter. Both advance atomically on
//! server-ack via a single fsync.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Atomically persist `state` to `path` via tmp+fsync+rename + parent dir
/// fsync (POSIX). Safe across crash: caller never observes a partial write.
pub fn store(path: &Path, state: &SenderState) -> Result<(), StateError> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| StateError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("sender-offset.json"),
        std::process::id()
    ));
    let bytes = serde_json::to_vec(state).expect("serialize SenderState");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|source| StateError::Io { path: tmp.clone(), source })?;
        f.write_all(&bytes).map_err(|source| StateError::Io { path: tmp.clone(), source })?;
        f.sync_all().map_err(|source| StateError::Io { path: tmp.clone(), source })?;
    }
    std::fs::rename(&tmp, path).map_err(|source| StateError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|source| StateError::Io { path: parent.to_path_buf(), source })?;
        dir.sync_all().map_err(|source| StateError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

/// Boot recovery: loads state from disk, falling back to `empty()` if
/// the file is absent (first-run). Surfaces parse errors so the operator
/// sees corruption immediately rather than silently resetting offsets.
pub fn load_or_empty(path: &Path) -> Result<SenderState, StateError> {
    Ok(load(path)?.unwrap_or_else(SenderState::empty))
}

/// Load `sender-offset.json`; returns `Ok(None)` if the file is absent
/// (first run); returns `Err` for read or parse failures.
pub fn load(path: &Path) -> Result<Option<SenderState>, StateError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(StateError::Io { path: path.to_path_buf(), source }),
    };
    let s = serde_json::from_slice(&bytes).map_err(|source| StateError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Some(s))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SenderState {
    /// Filename of the JSONL segment the sender is currently shipping.
    pub current_file: String,
    /// Byte offset within `current_file` past the last acked event.
    pub byte_offset: u64,
    /// Per-host monotonic counter of the last acked event.
    pub last_acked_sequence: u64,
}

impl SenderState {
    pub fn empty() -> Self {
        SenderState {
            current_file: String::new(),
            byte_offset: 0,
            last_acked_sequence: 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("io {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("json parse {path}: {source}")]
    Parse { path: PathBuf, source: serde_json::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trips_through_json() {
        let s = SenderState {
            current_file: "events-2026-05-15-002.jsonl".into(),
            byte_offset: 18234212,
            last_acked_sequence: 71_503,
        };
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: SenderState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn empty_state_starts_at_zero() {
        let s = SenderState::empty();
        assert_eq!(s.byte_offset, 0);
        assert_eq!(s.last_acked_sequence, 0);
        assert!(s.current_file.is_empty());
    }

    #[test]
    fn store_then_load_roundtrips() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender-offset.json");
        let s = SenderState {
            current_file: "events-1.jsonl".into(),
            byte_offset: 4096,
            last_acked_sequence: 10,
        };
        store(&p, &s).unwrap();
        let loaded = load(&p).unwrap().unwrap();
        assert_eq!(loaded, s);
    }

    #[test]
    fn load_returns_none_when_file_absent() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender-offset.json");
        assert!(load(&p).unwrap().is_none());
    }

    #[test]
    fn store_overwrites_atomically() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender-offset.json");
        store(&p, &SenderState {
            current_file: "a".into(), byte_offset: 1, last_acked_sequence: 1,
        }).unwrap();
        store(&p, &SenderState {
            current_file: "b".into(), byte_offset: 2, last_acked_sequence: 2,
        }).unwrap();
        let loaded = load(&p).unwrap().unwrap();
        assert_eq!(loaded.current_file, "b");
        assert_eq!(loaded.byte_offset, 2);
        assert_eq!(loaded.last_acked_sequence, 2);
    }

    #[test]
    fn store_leaves_no_tmp_files() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender-offset.json");
        store(&p, &SenderState::empty()).unwrap();
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftover.is_empty());
    }

    #[test]
    fn load_or_empty_returns_empty_when_file_absent() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender-offset.json");
        let s = load_or_empty(&p).unwrap();
        assert_eq!(s, SenderState::empty());
    }

    #[test]
    fn load_or_empty_returns_loaded_when_file_present() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender-offset.json");
        let stored = SenderState {
            current_file: "events-99.jsonl".into(),
            byte_offset: 999,
            last_acked_sequence: 9,
        };
        store(&p, &stored).unwrap();
        assert_eq!(load_or_empty(&p).unwrap(), stored);
    }
}
