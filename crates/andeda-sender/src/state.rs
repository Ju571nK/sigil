//! Sender offset state persisted to `sender-offset.json`.
//!
//! Spec §3.8.3 — `byte_offset` is a file position; `last_acked_sequence`
//! is the per-host monotonic event counter. Both advance atomically on
//! server-ack via a single fsync.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

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
}
