//! Reverse-chronological JSONL scan for /v1/events. Walks
//! events_out_dir/<host_id>/received-*.jsonl files in date desc order,
//! line-by-line in memory, applies filters, stops at limit.

use serde_json::Value;
use sigil_core::event::Event;
use std::path::Path;
use uuid::Uuid;

/// Extract the UNIX-ms timestamp from a UUIDv7 (first 48 bits, big-endian).
fn uuid_v7_unix_ms(uid: Uuid) -> u64 {
    let b = uid.as_bytes();
    ((b[0] as u64) << 40)
        | ((b[1] as u64) << 32)
        | ((b[2] as u64) << 24)
        | ((b[3] as u64) << 16)
        | ((b[4] as u64) << 8)
        | (b[5] as u64)
}

/// Find a single event by id using the UUIDv7 timestamp to target the date file,
/// with a ±1 day window for agent/server clock skew. Returns the raw JSON line if
/// the matching event_id is found, else `Ok(None)`.
pub fn find_by_id(events_out_dir: &Path, event_id: Uuid) -> std::io::Result<Option<Value>> {
    let ms = uuid_v7_unix_ms(event_id);
    let secs = (ms / 1000) as i64;
    let center = match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let day = time::Duration::days(1);
    let dates: [String; 3] = [
        date_str(center - day),
        date_str(center),
        date_str(center + day),
    ];
    let needle = event_id.to_string();

    let hosts = match std::fs::read_dir(events_out_dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    for h in hosts.flatten() {
        let name = match h.file_name().to_str().map(str::to_string) {
            Some(s) => s,
            None => continue,
        };
        if name.starts_with('.') {
            continue;
        }
        for d in &dates {
            let path = h.path().join(format!("received-{d}.jsonl"));
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            for line in bytes.split(|&c| c == b'\n') {
                if line.is_empty() {
                    continue;
                }
                let v: Value = match serde_json::from_slice(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("event_id").and_then(|x| x.as_str()) == Some(needle.as_str()) {
                    return Ok(Some(v));
                }
            }
        }
    }
    Ok(None)
}

fn date_str(t: time::OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
}

#[derive(Default, Debug, Clone)]
pub struct ScanFilters {
    pub cursor: Option<Uuid>, // skip events with event_id >= cursor
    pub host_ids: Option<Vec<String>>,
    pub since: Option<time::OffsetDateTime>,
    pub until: Option<time::OffsetDateTime>,
    pub evidence_kinds: Option<Vec<String>>, // snake_case "kind"
    pub severity: Option<Vec<String>>,
    pub source: Option<Vec<String>>,
    pub min_ai_guard_bucket: Option<String>,
    pub limit: usize,
}

/// Result of a scan — events as raw JSON (consumer gets the wire-stable shape).
pub struct ScanResult {
    pub events: Vec<Value>,
    pub next_cursor: Option<Uuid>,
}

pub fn scan(events_out_dir: &Path, f: &ScanFilters) -> std::io::Result<ScanResult> {
    let mut out: Vec<Value> = Vec::new();
    let mut next_cursor: Option<Uuid> = None;

    let dirs = match std::fs::read_dir(events_out_dir) {
        Ok(it) => it,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ScanResult {
                events: out,
                next_cursor: None,
            })
        }
        Err(e) => return Err(e),
    };
    let mut files: Vec<(String, String, std::path::PathBuf)> = Vec::new();
    for d in dirs.flatten() {
        let name = match d.file_name().to_str().map(str::to_string) {
            Some(s) => s,
            None => continue,
        };
        if name.starts_with('.') {
            continue;
        }
        if let Some(hf) = &f.host_ids {
            if !hf.iter().any(|h| h == &name) {
                continue;
            }
        }
        if let Ok(items) = std::fs::read_dir(d.path()) {
            for it in items.flatten() {
                let fname = match it.file_name().to_str().map(str::to_string) {
                    Some(s) => s,
                    None => continue,
                };
                if fname.starts_with("received-") && fname.ends_with(".jsonl") {
                    files.push((name.clone(), fname, it.path()));
                }
            }
        }
    }
    // Sort file basenames desc (newest day first).
    files.sort_by_key(|f| std::cmp::Reverse(f.1.clone()));

    'outer: for (_host_id, _fname, path) in files {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Split into lines, reverse iterate.
        let mut lines: Vec<&[u8]> = bytes
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        lines.reverse();
        for line in lines {
            let event: Event = match serde_json::from_slice(line) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !filter_match(&event, f) {
                continue;
            }
            // raw JSON shape — re-parse so we don't re-serialize via sigil-core's Event Serialize
            // (preserves any forward-compatible unknown fields).
            let raw: Value = match serde_json::from_slice(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push(raw);
            if out.len() >= f.limit {
                next_cursor = Some(event.event_id);
                break 'outer;
            }
        }
    }

    Ok(ScanResult {
        events: out,
        next_cursor,
    })
}

fn filter_match(e: &Event, f: &ScanFilters) -> bool {
    if let Some(c) = f.cursor {
        // UUIDv7 lexicographic = time-ordered. Skip events >= cursor.
        if e.event_id >= c {
            return false;
        }
    }
    if let Some(since) = f.since {
        if e.ts < since {
            return false;
        }
    }
    if let Some(until) = f.until {
        if e.ts >= until {
            return false;
        }
    }
    if let Some(kinds) = &f.evidence_kinds {
        let kind = serde_json::to_value(&e.evidence)
            .ok()
            .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_string));
        match kind {
            Some(k) => {
                if !kinds.iter().any(|x| x == &k) {
                    return false;
                }
            }
            None => return false,
        }
    }
    if let Some(sev) = &f.severity {
        let s = match e.severity {
            sigil_core::event::Severity::Info => "info",
            sigil_core::event::Severity::Warn => "warn",
        };
        if !sev.iter().any(|x| x == s) {
            return false;
        }
    }
    if let Some(srcs) = &f.source {
        let s = match e.source {
            sigil_core::event::SourceKind::FileSystem => "file_system",
            sigil_core::event::SourceKind::Agent => "agent",
        };
        if !srcs.iter().any(|x| x == s) {
            return false;
        }
    }
    if let Some(min_bucket) = &f.min_ai_guard_bucket {
        if let sigil_core::event::Evidence::AiGuardRiskAssessed { bucket, .. } = &e.evidence {
            use sigil_core::event::AiGuardBucket::*;
            let rank = |b: sigil_core::event::AiGuardBucket| match b {
                Low => 1,
                Medium => 2,
                High => 3,
                Critical => 4,
            };
            let min_rank = match min_bucket.as_str() {
                "medium" => 2,
                "high" => 3,
                "critical" => 4,
                _ => 1,
            };
            if rank(*bucket) < min_rank {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn write_line(p: &std::path::Path, line: &serde_json::Value) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn evjson(host_id: &str, ts: &str, kind: &str) -> serde_json::Value {
        let evidence = match kind {
            "host_id_conflict" => json!({"kind": "host_id_conflict", "observed_status": 200}),
            "tls_failure" => json!({"kind": "tls_failure", "reason": "test"}),
            _ => json!({"kind": kind, "observed_status": 200}),
        };
        json!({
            "schema_version": 1,
            "event_id": uuid::Uuid::now_v7().to_string(),
            "ts": ts,
            "host_id": host_id,
            "agent_version": "0.5.0",
            "severity": "warn",
            "source": {"kind": "agent"},
            "subject": {"kind": "self"},
            "evidence": evidence,
            "target_id": null
        })
    }

    #[test]
    fn scan_returns_newest_first_within_limit() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join("h1");
        std::fs::create_dir_all(&host_dir).unwrap();
        let f1 = host_dir.join("received-2026-05-16.jsonl");
        let f2 = host_dir.join("received-2026-05-17.jsonl");
        write_line(
            &f1,
            &evjson("h1", "2026-05-16T12:00:00Z", "host_id_conflict"),
        );
        write_line(
            &f2,
            &evjson("h1", "2026-05-17T12:00:00Z", "host_id_conflict"),
        );
        let r = scan(
            dir.path(),
            &ScanFilters {
                limit: 10,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.events.len(), 2);
        // First (newest) should be 2026-05-17.
        assert_eq!(r.events[0]["ts"], "2026-05-17T12:00:00Z");
    }

    #[test]
    fn scan_filters_by_evidence_kind() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join("h1");
        std::fs::create_dir_all(&host_dir).unwrap();
        let f = host_dir.join("received-2026-05-17.jsonl");
        write_line(
            &f,
            &evjson("h1", "2026-05-17T11:00:00Z", "host_id_conflict"),
        );
        write_line(&f, &evjson("h1", "2026-05-17T12:00:00Z", "tls_failure"));
        let r = scan(
            dir.path(),
            &ScanFilters {
                limit: 10,
                evidence_kinds: Some(vec!["tls_failure".into()]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.events.len(), 1);
        assert_eq!(r.events[0]["evidence"]["kind"], "tls_failure");
    }

    #[test]
    fn find_by_id_targets_date_file_from_uuidv7() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join("h1");
        std::fs::create_dir_all(&host_dir).unwrap();
        let target = evjson("h1", "2026-05-17T12:00:00Z", "host_id_conflict");
        let target_id = target["event_id"].as_str().unwrap().to_string();
        let target_uuid = uuid::Uuid::parse_str(&target_id).unwrap();
        // Compute the date the UUIDv7 timestamp resolves to and write the line there.
        let ms = uuid_v7_unix_ms(target_uuid);
        let t = time::OffsetDateTime::from_unix_timestamp((ms / 1000) as i64).unwrap();
        let fname = format!(
            "received-{:04}-{:02}-{:02}.jsonl",
            t.year(),
            t.month() as u8,
            t.day()
        );
        let f_target = host_dir.join(&fname);
        write_line(&f_target, &target);
        // Decoy in a far-away file that must NOT be opened by find_by_id.
        let f_decoy = host_dir.join("received-2020-01-01.jsonl");
        write_line(
            &f_decoy,
            &evjson("h1", "2020-01-01T00:00:00Z", "host_id_conflict"),
        );
        let got = find_by_id(dir.path(), target_uuid).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap()["event_id"], target_id);
    }

    #[test]
    fn find_by_id_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join("h1");
        std::fs::create_dir_all(&host_dir).unwrap();
        let f = host_dir.join("received-2026-05-17.jsonl");
        write_line(
            &f,
            &evjson("h1", "2026-05-17T12:00:00Z", "host_id_conflict"),
        );
        let missing = uuid::Uuid::now_v7();
        assert!(find_by_id(dir.path(), missing).unwrap().is_none());
    }

    #[test]
    fn scan_emits_cursor_when_limit_reached() {
        let dir = tempdir().unwrap();
        let host_dir = dir.path().join("h1");
        std::fs::create_dir_all(&host_dir).unwrap();
        let f = host_dir.join("received-2026-05-17.jsonl");
        for _ in 0..5 {
            write_line(
                &f,
                &evjson("h1", "2026-05-17T12:00:00Z", "host_id_conflict"),
            );
        }
        let r = scan(
            dir.path(),
            &ScanFilters {
                limit: 3,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.events.len(), 3);
        assert!(r.next_cursor.is_some());
    }
}
