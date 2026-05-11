//! Per-host JSONL persistence + sequence-based dedup.
//!
//! Layout: `events_out_dir/<host_id>/received-YYYY-MM-DD.jsonl`, append mode.
//! Dedup: an in-memory `host_id → last_persisted_sequence` map is consulted
//! before each write and persisted to `high_water_path` (atomic tmp+rename)
//! after each batch, so a server restart does not re-persist already-seen
//! events when the sender resends a batch.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("io {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("json {0}")]
    Json(serde_json::Error),
}

/// In-memory high-water map. Wrap in a `Mutex` for shared use.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HighWater {
    /// host_id → highest persisted `sequence`.
    pub by_host: HashMap<String, u64>,
}

impl HighWater {
    /// Load from `path`; `Ok(default)` if the file is absent (first run).
    pub fn load(path: &Path) -> Result<Self, PersistError> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(PersistError::Json),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HighWater::default()),
            Err(source) => Err(PersistError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Atomically persist to `path` (tmp + rename).
    pub fn store(&self, path: &Path) -> Result<(), PersistError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|source| PersistError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let tmp = parent.join(format!(".high-water.{}.tmp", std::process::id()));
        let bytes = serde_json::to_vec(self).map_err(PersistError::Json)?;
        std::fs::write(&tmp, &bytes).map_err(|source| PersistError::Io {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, path).map_err(|source| PersistError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn get(&self, host_id: &str) -> u64 {
        self.by_host.get(host_id).copied().unwrap_or(0)
    }

    pub fn set(&mut self, host_id: &str, seq: u64) {
        let e = self.by_host.entry(host_id.to_string()).or_insert(0);
        if seq > *e {
            *e = seq;
        }
    }
}

/// One event ready to persist: its sequence and the opaque payload JSON.
pub struct PersistEvent<'a> {
    pub sequence: u64,
    pub payload: &'a JsonValue,
}

/// Append the given events for `host_id` to today's JSONL segment, skipping
/// any whose `sequence` is `<= high_water.get(host_id)`. Returns how many
/// were actually written. Updates `high_water` in memory but does NOT
/// persist it — the caller does that once per batch.
pub fn append_events(
    events_out_dir: &Path,
    host_id: &str,
    events: &[PersistEvent<'_>],
    high_water: &mut HighWater,
    now: OffsetDateTime,
) -> Result<usize, PersistError> {
    let host_dir = events_out_dir.join(host_id);
    std::fs::create_dir_all(&host_dir).map_err(|source| PersistError::Io {
        path: host_dir.clone(),
        source,
    })?;
    let basename = format!(
        "received-{:04}-{:02}-{:02}.jsonl",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    let path = host_dir.join(basename);

    let cur = high_water.get(host_id);
    let to_write: Vec<&PersistEvent<'_>> = events.iter().filter(|e| e.sequence > cur).collect();
    if to_write.is_empty() {
        return Ok(0);
    }

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| PersistError::Io {
            path: path.clone(),
            source,
        })?;
    let mut max_seq = cur;
    for e in &to_write {
        let mut line = serde_json::to_vec(e.payload).map_err(PersistError::Json)?;
        line.push(b'\n');
        f.write_all(&line).map_err(|source| PersistError::Io {
            path: path.clone(),
            source,
        })?;
        if e.sequence > max_seq {
            max_seq = e.sequence;
        }
    }
    f.sync_all().map_err(|source| PersistError::Io {
        path: path.clone(),
        source,
    })?;
    high_water.set(host_id, max_seq);
    Ok(to_write.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;
    use time::macros::datetime;

    #[test]
    fn writes_new_events_and_skips_dups() {
        let dir = tempdir().unwrap();
        let mut hw = HighWater::default();
        let now = datetime!(2026-05-11 12:00 UTC);
        let p1 = json!({"event_id":"a","sequence":1});
        let p2 = json!({"event_id":"b","sequence":2});
        let evs = [
            PersistEvent {
                sequence: 1,
                payload: &p1,
            },
            PersistEvent {
                sequence: 2,
                payload: &p2,
            },
        ];
        let n = append_events(dir.path(), "h1", &evs, &mut hw, now).unwrap();
        assert_eq!(n, 2);
        assert_eq!(hw.get("h1"), 2);

        // Resend the same batch — nothing new written.
        let n = append_events(dir.path(), "h1", &evs, &mut hw, now).unwrap();
        assert_eq!(n, 0);

        // Partial overlap: seq 2 (dup) + seq 3 (new) → 1 written.
        let p3 = json!({"event_id":"c","sequence":3});
        let evs2 = [
            PersistEvent {
                sequence: 2,
                payload: &p2,
            },
            PersistEvent {
                sequence: 3,
                payload: &p3,
            },
        ];
        let n = append_events(dir.path(), "h1", &evs2, &mut hw, now).unwrap();
        assert_eq!(n, 1);
        assert_eq!(hw.get("h1"), 3);

        // Disk has 3 lines for h1's segment.
        let seg = dir.path().join("h1").join("received-2026-05-11.jsonl");
        let body = std::fs::read_to_string(seg).unwrap();
        assert_eq!(body.matches('\n').count(), 3);
    }

    #[test]
    fn high_water_round_trips() {
        let dir = tempdir().unwrap();
        let p = dir.path().join(".high-water.json");
        let mut hw = HighWater::default();
        hw.set("h1", 42);
        hw.set("h2", 7);
        hw.store(&p).unwrap();
        let back = HighWater::load(&p).unwrap();
        assert_eq!(back.get("h1"), 42);
        assert_eq!(back.get("h2"), 7);
        assert_eq!(back.get("h3"), 0);
    }

    #[test]
    fn high_water_load_absent_is_empty() {
        let dir = tempdir().unwrap();
        let hw = HighWater::load(&dir.path().join("nope.json")).unwrap();
        assert_eq!(hw.get("x"), 0);
    }

    #[test]
    fn separate_hosts_get_separate_dirs() {
        let dir = tempdir().unwrap();
        let mut hw = HighWater::default();
        let now = datetime!(2026-05-11 0:00 UTC);
        let p = json!({"k":"v"});
        append_events(
            dir.path(),
            "alpha",
            &[PersistEvent {
                sequence: 1,
                payload: &p,
            }],
            &mut hw,
            now,
        )
        .unwrap();
        append_events(
            dir.path(),
            "beta",
            &[PersistEvent {
                sequence: 1,
                payload: &p,
            }],
            &mut hw,
            now,
        )
        .unwrap();
        assert!(dir
            .path()
            .join("alpha")
            .join("received-2026-05-11.jsonl")
            .exists());
        assert!(dir
            .path()
            .join("beta")
            .join("received-2026-05-11.jsonl")
            .exists());
        assert_eq!(hw.get("alpha"), 1);
        assert_eq!(hw.get("beta"), 1);
    }
}
