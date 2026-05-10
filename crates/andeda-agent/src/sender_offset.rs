//! Reader for `sender-offset.json` — the on-disk record of how far the
//! Plan B `andeda-sender` has consumed in the agent's `events/` directory.
//!
//! Schema (spec §3.9):
//! ```json
//! {
//!   "current_segment": "events-2026-05-15-002.jsonl",
//!   "byte_offset": 1234567,
//!   "updated_at": "2026-05-15T12:34:56Z"
//! }
//! ```
//!
//! - File does not exist → `Ok(None)` ("no sender ever ran" — Plan A
//!   foundation behavior; the GC pretends nothing has been consumed).
//! - File exists but malformed → `Err(...)` (operators triage; the agent
//!   logs and falls back to "treat as no consumption" for safety).

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SenderOffset {
    /// Filename (NOT full path) of the segment the sender is currently shipping.
    pub current_segment: String,
    /// Byte offset within `current_segment` up to which the sender has
    /// successfully shipped + acknowledged.
    pub byte_offset: u64,
    /// Last time the sender wrote this file. Informational; the GC does not
    /// use this — staleness is detected by the soft-floor TIME threshold.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Error)]
pub enum SenderOffsetError {
    /// I/O failure reading the file (other than "not found").
    #[error("io: {0}")]
    Io(std::io::Error),
    /// JSON parse failure.
    #[error("json: {0}")]
    Json(serde_json::Error),
}

/// Read `sender-offset.json` from `events_dir`.
/// Returns `Ok(None)` if the file does not exist.
pub fn read(events_dir: &Path) -> Result<Option<SenderOffset>, SenderOffsetError> {
    let path = events_dir.join("sender-offset.json");
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(SenderOffsetError::Io(e)),
    };
    let off: SenderOffset = serde_json::from_slice(&bytes).map_err(SenderOffsetError::Json)?;
    Ok(Some(off))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use time::macros::datetime;

    #[test]
    fn missing_file_returns_none() {
        let dir = tempdir().unwrap();
        assert_eq!(read(dir.path()).unwrap(), None);
    }

    #[test]
    fn well_formed_file_round_trips() {
        let dir = tempdir().unwrap();
        let off = SenderOffset {
            current_segment: "events-2026-05-15-002.jsonl".into(),
            byte_offset: 1234567,
            updated_at: datetime!(2026-05-15 12:34:56 UTC),
        };
        std::fs::write(
            dir.path().join("sender-offset.json"),
            serde_json::to_vec(&off).unwrap(),
        )
        .unwrap();
        let loaded = read(dir.path()).unwrap().unwrap();
        assert_eq!(loaded, off);
    }

    #[test]
    fn malformed_json_returns_error() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("sender-offset.json"), b"not json").unwrap();
        assert!(matches!(read(dir.path()), Err(SenderOffsetError::Json(_))));
    }

    #[test]
    fn missing_required_field_returns_error() {
        let dir = tempdir().unwrap();
        // missing `byte_offset`
        std::fs::write(
            dir.path().join("sender-offset.json"),
            br#"{"current_segment":"x","updated_at":"2026-05-15T00:00:00Z"}"#,
        )
        .unwrap();
        assert!(matches!(read(dir.path()), Err(SenderOffsetError::Json(_))));
    }

    #[test]
    fn timestamp_must_be_rfc3339() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("sender-offset.json"),
            br#"{"current_segment":"x","byte_offset":0,"updated_at":"not-a-date"}"#,
        )
        .unwrap();
        assert!(matches!(read(dir.path()), Err(SenderOffsetError::Json(_))));
    }
}
