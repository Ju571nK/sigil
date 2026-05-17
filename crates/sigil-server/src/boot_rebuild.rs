//! Boot rebuild — walk events_out_dir/<host_id>/received-YYYY-MM-DD.jsonl
//! in chronological order, apply each event to a HostSummary, and return the
//! built map for swap-in to FleetIndex.

use crate::fleet_index::HostSummary;
use crate::fleet_index_update::apply_event;
use sigil_core::event::Event;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// Walk all per-host JSONL files under `events_out_dir`, apply each line to
/// a HostSummary, return the built map. Corrupt lines are skipped with a
/// `tracing::warn!`. Caller (`main.rs`) calls `FleetIndex::replace(...)` with
/// the result before opening the HTTP listener.
pub fn rebuild_from_jsonl(events_out_dir: &Path) -> std::io::Result<HashMap<String, HostSummary>> {
    let mut out: HashMap<String, HostSummary> = HashMap::new();

    let entries = match std::fs::read_dir(events_out_dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };

    let mut files: Vec<(PathBuf, String)> = Vec::new();
    for ent in entries.flatten() {
        let host_dir = ent.path();
        if !host_dir.is_dir() {
            continue;
        }
        let host_id = match ent.file_name().to_str().map(str::to_string) {
            Some(s) => s,
            None => continue,
        };
        if host_id.starts_with('.') {
            continue; // skip .high-water.json and friends
        }
        let host_files = match std::fs::read_dir(&host_dir) {
            Ok(it) => it,
            Err(_) => continue,
        };
        for f in host_files.flatten() {
            let path = f.path();
            let name = match f.file_name().to_str().map(str::to_string) {
                Some(s) => s,
                None => continue,
            };
            if name.starts_with("received-") && name.ends_with(".jsonl") {
                files.push((path, name));
            }
        }
    }
    // Sort by file basename (the YYYY-MM-DD prefix makes this chronological).
    files.sort_by(|(_, a), (_, b)| a.cmp(b));

    for (path, _name) in files {
        let f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(?path, error = ?e, "skip unreadable jsonl");
                continue;
            }
        };
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        loop {
            line.clear();
            let n = match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(?path, error = ?e, "read_line failed; stop file");
                    break;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Event>(line.trim_end()) {
                Ok(event) => {
                    let entry = out
                        .entry(event.host_id.clone())
                        .or_insert_with(|| HostSummary::new(event.host_id.clone()));
                    apply_event(entry, &event);
                }
                Err(e) => {
                    tracing::warn!(?path, error = ?e, bytes = n, "skip corrupt jsonl line");
                }
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn write_line(p: &Path, line: &serde_json::Value) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn host_meta_event(host_id: &str, hostname: &str, ts: &str) -> serde_json::Value {
        json!({
            "schema_version": 1,
            "event_id": uuid::Uuid::now_v7().to_string(),
            "ts": ts,
            "host_id": host_id,
            "agent_version": "0.5.0",
            "severity": "info",
            "source": {"kind": "agent"},
            "subject": {"kind": "self"},
            "evidence": {
                "kind": "host_meta_snapshot",
                "snapshot": {
                    "hostname": hostname,
                    "os_name": null, "os_version": null, "kernel_version": null,
                    "architecture": null, "interfaces": [],
                    "default_gateway_v4": null, "default_gateway_v6": null,
                    "dns_servers": []
                },
                "is_reattestation": false
            },
            "target_id": null
        })
    }

    #[test]
    fn rebuild_empty_dir_returns_empty_map() {
        let dir = tempdir().unwrap();
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn rebuild_nonexistent_dir_returns_empty_map() {
        let map = rebuild_from_jsonl(Path::new("/nonexistent/never/exists")).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn rebuild_picks_up_host_meta_snapshot() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join("h1");
        std::fs::create_dir_all(&host_dir).unwrap();
        let file = host_dir.join("received-2026-05-17.jsonl");
        write_line(
            &file,
            &host_meta_event("h1", "alice", "2026-05-17T12:00:00Z"),
        );
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        assert_eq!(map.len(), 1);
        let h = map.get("h1").unwrap();
        assert_eq!(h.hostname(), Some("alice"));
    }

    #[test]
    fn rebuild_applies_events_in_chronological_order_across_files() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join("h1");
        std::fs::create_dir_all(&host_dir).unwrap();
        let f_old = host_dir.join("received-2026-05-16.jsonl");
        let f_new = host_dir.join("received-2026-05-17.jsonl");
        write_line(
            &f_old,
            &host_meta_event("h1", "old-name", "2026-05-16T12:00:00Z"),
        );
        write_line(
            &f_new,
            &host_meta_event("h1", "new-name", "2026-05-17T12:00:00Z"),
        );
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        // newer overrides older
        assert_eq!(map.get("h1").unwrap().hostname(), Some("new-name"));
    }

    #[test]
    fn rebuild_skips_corrupt_lines() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join("h1");
        std::fs::create_dir_all(&host_dir).unwrap();
        let file = host_dir.join("received-2026-05-17.jsonl");
        write_line(&file, &serde_json::json!("not-an-object"));
        write_line(
            &file,
            &host_meta_event("h1", "alice", "2026-05-17T12:00:00Z"),
        );
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        // good line still applied; bad line warned + skipped
        assert_eq!(map.get("h1").unwrap().hostname(), Some("alice"));
    }

    #[test]
    fn rebuild_ignores_hidden_files_like_high_water() {
        let dir = tempdir().unwrap();
        // not a host_id dir — should be skipped
        std::fs::write(dir.path().join(".high-water.json"), "{}").unwrap();
        let map = rebuild_from_jsonl(dir.path()).unwrap();
        assert!(map.is_empty());
    }
}
