//! Host-side dead-letter / audit spool writer.
//!
//! Spec §3.8.3 — best-effort, at-least-once. Caller writes BEFORE the
//! offset advance fsync. Failure to write here logs once and proceeds
//! (the host audit is a debugging aid, not source-of-truth).

use andeda_core::event::Event;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum DeadLetterError {
    #[error("io {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("serialize: {0}")]
    Serialize(serde_json::Error),
}

/// Append one event line to today's `sender-dead-letter-YYYY-MM-DD.jsonl`
/// in `dir`. Creates the file if missing; one fsync per line.
pub fn append(dir: &Path, event: &Event) -> Result<(), DeadLetterError> {
    std::fs::create_dir_all(dir).map_err(|source| DeadLetterError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let now = OffsetDateTime::now_utc();
    let basename = format!(
        "sender-dead-letter-{:04}-{:02}-{:02}.jsonl",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    let path = dir.join(basename);
    let mut bytes = serde_json::to_vec(event).map_err(DeadLetterError::Serialize)?;
    bytes.push(b'\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| DeadLetterError::Io {
            path: path.clone(),
            source,
        })?;
    f.write_all(&bytes).map_err(|source| DeadLetterError::Io {
        path: path.clone(),
        source,
    })?;
    f.sync_all().map_err(|source| DeadLetterError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use andeda_core::event::{
        Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
    };
    use tempfile::tempdir;

    fn sample_event() -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            event_id: uuid::Uuid::nil(),
            ts: OffsetDateTime::now_utc(),
            host_id: "h".into(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::EventUnprocessableLocal {
                original_event_id: uuid::Uuid::nil(),
                server_reason: "schema_mismatch".into(),
            },
            target_id: None,
        }
    }

    #[test]
    fn append_creates_file_with_one_jsonl_line() {
        let dir = tempdir().unwrap();
        append(dir.path(), &sample_event()).unwrap();
        // Find the file (filename has date suffix).
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("sender-dead-letter-")
            })
            .collect();
        assert_eq!(entries.len(), 1);
        let body = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(body.ends_with('\n'));
        assert_eq!(body.matches('\n').count(), 1);
    }

    #[test]
    fn two_appends_produce_two_lines() {
        let dir = tempdir().unwrap();
        append(dir.path(), &sample_event()).unwrap();
        append(dir.path(), &sample_event()).unwrap();
        let entry = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("sender-dead-letter-")
            })
            .unwrap();
        let body = std::fs::read_to_string(entry.path()).unwrap();
        assert_eq!(body.matches('\n').count(), 2);
    }
}
