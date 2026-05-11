//! Reads the next batch of events from a JSONL spool segment.
//!
//! Caller drives by passing the current `SenderState` and gets back a
//! `BatchManifest` plus parsed events. Pure I/O wrapper; no HTTP, no
//! offset advance.

use crate::manifest::{BatchManifest, ByteRange, ManifestEntry};
use crate::state::SenderState;
use crate::wire::EventEntry;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum BatchReadError {
    #[error("io {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("json parse at offset {offset}: {source}")]
    Parse {
        offset: u64,
        source: serde_json::Error,
    },
    #[error("event missing event_id at offset {offset}")]
    MissingEventId { offset: u64 },
}

/// Subset of an Sigil Event needed by the sender (just the id).
/// The full payload is forwarded to the server as opaque JSON.
#[derive(Deserialize)]
struct EventIdProbe {
    event_id: Uuid,
}

/// Read up to `max_events` events (or `max_bytes`, whichever first) from
/// the segment at `events_dir/state.current_file`, starting at
/// `state.byte_offset`. Returns the parsed wire-ready entries plus the
/// manifest mapping event_id → (byte_range, provisional_sequence).
pub fn read_next_batch(
    events_dir: &Path,
    state: &SenderState,
    max_events: usize,
    max_bytes: usize,
) -> Result<(Vec<EventEntry>, BatchManifest), BatchReadError> {
    let path = events_dir.join(&state.current_file);
    let mut file = std::fs::File::open(&path).map_err(|source| BatchReadError::Io {
        path: path.clone(),
        source,
    })?;
    file.seek(SeekFrom::Start(state.byte_offset))
        .map_err(|source| BatchReadError::Io {
            path: path.clone(),
            source,
        })?;
    let mut reader = BufReader::new(file);

    let mut events = Vec::new();
    let mut manifest = BatchManifest::new();
    let mut current_offset = state.byte_offset;
    let mut bytes_consumed = 0usize;
    let mut next_seq = state.last_acked_sequence;

    loop {
        if events.len() >= max_events {
            break;
        }
        if bytes_consumed >= max_bytes {
            break;
        }
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|source| BatchReadError::Io {
                path: path.clone(),
                source,
            })?;
        if n == 0 {
            break;
        } // EOF
        if !line.ends_with('\n') {
            // Truncated trailing line — leave it for next iteration after producer flushes.
            break;
        }
        let start = current_offset;
        let end = start + n as u64;
        // Strip trailing newline before JSON parse.
        let json_slice = &line[..line.len() - 1];
        let probe: EventIdProbe =
            serde_json::from_str(json_slice).map_err(|source| BatchReadError::Parse {
                offset: start,
                source,
            })?;
        let payload: serde_json::Value =
            serde_json::from_str(json_slice).map_err(|source| BatchReadError::Parse {
                offset: start,
                source,
            })?;
        next_seq += 1;
        manifest.push(ManifestEntry {
            event_id: probe.event_id,
            byte_range: ByteRange { start, end },
            provisional_sequence: next_seq,
            current_file: state.current_file.clone(),
        });
        events.push(EventEntry {
            event_id: probe.event_id,
            sequence: next_seq,
            payload,
        });
        current_offset = end;
        bytes_consumed += n;
    }

    Ok((events, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_events(dir: &Path, name: &str, events: &[(Uuid, &str)]) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        for (id, body) in events {
            let line = format!(r#"{{"event_id":"{id}","payload":{body}}}"#);
            writeln!(f, "{line}").unwrap();
        }
        p
    }

    #[test]
    fn reads_two_events_from_offset_zero() {
        let dir = tempdir().unwrap();
        let id_a = Uuid::from_u128(1);
        let id_b = Uuid::from_u128(2);
        write_events(
            dir.path(),
            "events-1.jsonl",
            &[(id_a, r#""a""#), (id_b, r#""b""#)],
        );
        let state = SenderState {
            current_file: "events-1.jsonl".into(),
            byte_offset: 0,
            last_acked_sequence: 0,
        };
        let (events, manifest) = read_next_batch(dir.path(), &state, 256, 1_000_000).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, id_a);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].sequence, 2);
        assert_eq!(manifest.len(), 2);
    }

    #[test]
    fn respects_max_events() {
        let dir = tempdir().unwrap();
        let id_a = Uuid::from_u128(1);
        let id_b = Uuid::from_u128(2);
        write_events(
            dir.path(),
            "events-1.jsonl",
            &[(id_a, r#""a""#), (id_b, r#""b""#)],
        );
        let state = SenderState {
            current_file: "events-1.jsonl".into(),
            byte_offset: 0,
            last_acked_sequence: 0,
        };
        let (events, _) = read_next_batch(dir.path(), &state, 1, 1_000_000).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn skips_truncated_trailing_line() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("events-1.jsonl");
        // Two events, second one missing trailing \n.
        let id_a = Uuid::from_u128(1);
        let id_b = Uuid::from_u128(2);
        let body = format!(
            "{{\"event_id\":\"{id_a}\",\"payload\":\"a\"}}\n{{\"event_id\":\"{id_b}\",\"payload\":\"b\"}}"
        );
        std::fs::write(&p, body.as_bytes()).unwrap();
        let state = SenderState {
            current_file: "events-1.jsonl".into(),
            byte_offset: 0,
            last_acked_sequence: 0,
        };
        let (events, _) = read_next_batch(dir.path(), &state, 256, 1_000_000).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, id_a);
    }

    #[test]
    fn missing_segment_is_io_error() {
        let dir = tempdir().unwrap();
        let state = SenderState {
            current_file: "missing.jsonl".into(),
            byte_offset: 0,
            last_acked_sequence: 0,
        };
        let err = read_next_batch(dir.path(), &state, 256, 1_000_000).unwrap_err();
        assert!(matches!(err, BatchReadError::Io { .. }));
    }
}
