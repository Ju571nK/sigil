//! Corrupt JSONL line must not break boot or /v1/events.
use sigil_server::boot_rebuild::rebuild_from_jsonl;
use sigil_server::jsonl_scan::{scan, ScanFilters};

fn good_line() -> String {
    let v = serde_json::json!({
        "schema_version": 1,
        "event_id": uuid::Uuid::now_v7().to_string(),
        "ts": "2026-05-17T12:00:00Z",
        "host_id": "h1", "agent_version": "0.5.0",
        "severity": "info", "source": {"kind": "agent"}, "subject": {"kind": "self"},
        "evidence": {"kind": "host_id_conflict", "observed_status": 200},
        "target_id": null
    });
    format!("{v}\n")
}

#[test]
fn boot_rebuild_skips_corrupt_lines() {
    let dir = tempfile::tempdir().unwrap();
    let host_dir = dir.path().join("h1");
    std::fs::create_dir_all(&host_dir).unwrap();
    let f = host_dir.join("received-2026-05-17.jsonl");
    let body = format!("{}{}{}", good_line(), "{not json}\n", good_line());
    std::fs::write(&f, body).unwrap();
    let map = rebuild_from_jsonl(dir.path()).unwrap();
    assert_eq!(map.len(), 1); // good lines applied, bad skipped
}

#[test]
fn jsonl_scan_skips_corrupt_lines() {
    let dir = tempfile::tempdir().unwrap();
    let host_dir = dir.path().join("h1");
    std::fs::create_dir_all(&host_dir).unwrap();
    let f = host_dir.join("received-2026-05-17.jsonl");
    let body = format!("{}{}{}", good_line(), "{not json}\n", good_line());
    std::fs::write(&f, body).unwrap();
    let r = scan(dir.path(), &ScanFilters { limit: 10, ..Default::default() }).unwrap();
    assert_eq!(r.events.len(), 2);
}
