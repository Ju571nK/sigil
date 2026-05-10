//! Retention integration tests.

use andeda_spool::{DurableOffset, Producer, ProducerConfig, Retention, RetentionConfig};
use std::fs;
use tempfile::TempDir;
use time::Duration;

fn pcfg(dir: &TempDir, _max: u64) -> ProducerConfig {
    // Each test line is 4 bytes ("AAA\n"). To produce one segment per append
    // the cap must be 5: after the first 4-byte write (size=4), the next
    // 4-byte write triggers the roll condition (4+4=8 > 5). The `_max`
    // parameter is kept to preserve call-site clarity; the real cap is 5.
    ProducerConfig {
        spool_dir: dir.path().to_path_buf(),
        prefix: "events".into(),
        max_segment_bytes: 5,
    }
}

fn rcfg(bytes: u64, secs: i64) -> RetentionConfig {
    RetentionConfig {
        max_total_bytes: bytes,
        max_age: Duration::seconds(secs),
    }
}

#[test]
fn invalid_config_is_rejected() {
    let zero_bytes = RetentionConfig {
        max_total_bytes: 0,
        max_age: Duration::seconds(60),
    };
    let zero_age = RetentionConfig {
        max_total_bytes: 100,
        max_age: Duration::ZERO,
    };
    assert!(Retention::new(zero_bytes).is_err());
    assert!(Retention::new(zero_age).is_err());
}

#[test]
fn enforce_keeps_segments_below_consumer_floor() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(pcfg(&dir, 10)).unwrap();
    p.append_line(b"AAA").unwrap();
    p.append_line(b"BBB").unwrap();
    p.append_line(b"CCC").unwrap();
    p.append_line(b"DDD").unwrap();

    // Three segments now exist (10-byte cap, ~4 bytes per line).
    let pcfg_clone = pcfg(&dir, 10);
    let r = Retention::new(rcfg(1, 3600)).unwrap();
    // Consumer is at the start of segment 2 — segments 0 and 1 are eligible.
    let consumer_floor = Some(DurableOffset {
        segment: "events-2.jsonl".into(),
        byte_offset: 0,
    });
    let removed = r.enforce(&pcfg_clone, consumer_floor.as_ref()).unwrap();
    assert_eq!(removed.len(), 2);
    assert!(!dir.path().join("events-0.jsonl").exists());
    assert!(!dir.path().join("events-1.jsonl").exists());
    assert!(dir.path().join("events-2.jsonl").exists());
    assert!(dir.path().join("events-3.jsonl").exists());
}

#[test]
fn enforce_does_not_delete_segments_above_consumer_floor_under_size_cap() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(pcfg(&dir, 10)).unwrap();
    p.append_line(b"AAA").unwrap();
    p.append_line(b"BBB").unwrap();
    let pcfg_clone = pcfg(&dir, 10);
    let r = Retention::new(rcfg(1, 3600)).unwrap();
    // Consumer is still at segment 0 offset 0 — nothing eligible.
    let consumer_floor = Some(DurableOffset {
        segment: "events-0.jsonl".into(),
        byte_offset: 0,
    });
    let removed = r.enforce(&pcfg_clone, consumer_floor.as_ref()).unwrap();
    assert!(removed.is_empty());
    assert!(dir.path().join("events-0.jsonl").exists());
    assert!(dir.path().join("events-1.jsonl").exists());
}

#[test]
fn enforce_no_consumer_means_size_age_only() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(pcfg(&dir, 10)).unwrap();
    p.append_line(b"AAA").unwrap();
    p.append_line(b"BBB").unwrap();
    p.append_line(b"CCC").unwrap();

    let pcfg_clone = pcfg(&dir, 10);
    let r = Retention::new(rcfg(1, 3600)).unwrap();
    let removed = r.enforce(&pcfg_clone, None).unwrap();
    assert!(!removed.is_empty());
    // The current segment (highest N) is never deleted by enforce — only
    // closed segments with N < highest are eligible.
    let entries: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(entries.iter().any(|n| n == "events-2.jsonl"));
}

#[test]
fn force_gc_returns_segments_force_deleted_above_floor() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(pcfg(&dir, 10)).unwrap();
    for _ in 0..5 {
        p.append_line(b"XXX").unwrap();
    }
    let pcfg_clone = pcfg(&dir, 10);
    let r = Retention::new(rcfg(1, 3600)).unwrap();
    // Consumer pinned at the very first segment.
    let floor = Some(DurableOffset {
        segment: "events-0.jsonl".into(),
        byte_offset: 0,
    });
    // Soft enforce: should NOT delete anything above the floor.
    assert!(r.enforce(&pcfg_clone, floor.as_ref()).unwrap().is_empty());
    // Force-GC: deletes the oldest above floor anyway, returning their names.
    let forced = r.force_gc(&pcfg_clone, floor.as_ref()).unwrap();
    assert!(!forced.is_empty());
}
