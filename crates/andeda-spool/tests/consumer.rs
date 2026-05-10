//! Consumer + Checkpoint integration tests.

use andeda_spool::{Checkpoint, Consumer, DurableOffset, Producer, ProducerConfig};
use std::time::Duration;
use tempfile::TempDir;

fn make_pcfg(dir: &TempDir) -> ProducerConfig {
    ProducerConfig {
        spool_dir: dir.path().to_path_buf(),
        prefix: "events".into(),
        max_segment_bytes: 64,
    }
}

#[test]
fn consumer_reads_existing_lines_in_order() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(make_pcfg(&dir)).unwrap();
    p.append_line(b"alpha").unwrap();
    p.append_line(b"beta").unwrap();
    p.append_line(b"gamma").unwrap();

    let cp_path = dir.path().join("consumer.json");
    let mut cp = Checkpoint::open(&cp_path).unwrap();
    let mut c = Consumer::open(dir.path(), "events", &mut cp).unwrap();

    let r0 = c
        .next_with_timeout(Duration::from_millis(100))
        .unwrap()
        .unwrap();
    let r1 = c
        .next_with_timeout(Duration::from_millis(100))
        .unwrap()
        .unwrap();
    let r2 = c
        .next_with_timeout(Duration::from_millis(100))
        .unwrap()
        .unwrap();
    assert_eq!(r0.bytes, b"alpha");
    assert_eq!(r1.bytes, b"beta");
    assert_eq!(r2.bytes, b"gamma");
}

#[test]
fn consumer_resumes_from_checkpoint_after_drop() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(make_pcfg(&dir)).unwrap();
    for s in &["one", "two", "three"] {
        p.append_line(s.as_bytes()).unwrap();
    }
    let cp_path = dir.path().join("consumer.json");

    // First session: read two, advance, drop.
    {
        let mut cp = Checkpoint::open(&cp_path).unwrap();
        let mut c = Consumer::open(dir.path(), "events", &mut cp).unwrap();
        let r = c
            .next_with_timeout(Duration::from_millis(100))
            .unwrap()
            .unwrap();
        assert_eq!(r.bytes, b"one");
        cp.advance(r.offset).unwrap();
        let r = c
            .next_with_timeout(Duration::from_millis(100))
            .unwrap()
            .unwrap();
        assert_eq!(r.bytes, b"two");
        cp.advance(r.offset).unwrap();
    }

    // Second session: should resume at "three".
    let mut cp = Checkpoint::open(&cp_path).unwrap();
    let mut c = Consumer::open(dir.path(), "events", &mut cp).unwrap();
    let r = c
        .next_with_timeout(Duration::from_millis(100))
        .unwrap()
        .unwrap();
    assert_eq!(r.bytes, b"three");
}

#[test]
fn consumer_crosses_segment_boundary() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(make_pcfg(&dir)).unwrap();
    // 64-byte cap; "AAAAAAAAAAAAAAAAAAAA" (20+1) repeated forces rolls.
    for s in &[
        "AAAAAAAAAAAAAAAAAAAA",
        "BBBBBBBBBBBBBBBBBBBB",
        "CCCCCCCCCCCCCCCCCCCC",
        "DDDD",
    ] {
        p.append_line(s.as_bytes()).unwrap();
    }
    let cp_path = dir.path().join("consumer.json");
    let mut cp = Checkpoint::open(&cp_path).unwrap();
    let mut c = Consumer::open(dir.path(), "events", &mut cp).unwrap();

    let mut got = Vec::new();
    for _ in 0..4 {
        let r = c
            .next_with_timeout(Duration::from_millis(100))
            .unwrap()
            .unwrap();
        got.push(String::from_utf8(r.bytes).unwrap());
    }
    assert_eq!(
        got,
        [
            "AAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBB",
            "CCCCCCCCCCCCCCCCCCCC",
            "DDDD"
        ]
    );
}

#[test]
fn checkpoint_advance_is_atomic_via_tmp_rename() {
    let dir = TempDir::new().unwrap();
    let cp_path = dir.path().join("consumer.json");
    let mut cp = Checkpoint::open(&cp_path).unwrap();
    cp.advance(DurableOffset {
        segment: "events-0.jsonl".into(),
        byte_offset: 42,
    })
    .unwrap();
    let raw = std::fs::read_to_string(&cp_path).unwrap();
    assert!(raw.contains("\"byte_offset\":42"));
    assert!(raw.contains("\"events-0.jsonl\""));
    // No leftover .tmp.
    assert!(!cp_path.with_extension("json.tmp").exists());
}

#[test]
fn checkpoint_open_returns_none_position_for_fresh_path() {
    let dir = TempDir::new().unwrap();
    let cp = Checkpoint::open(dir.path().join("absent.json")).unwrap();
    assert_eq!(cp.position(), None);
}
