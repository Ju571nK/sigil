//! Producer integration tests.

use sigil_spool::{Producer, ProducerConfig, ProducerError};
use std::fs;
use tempfile::TempDir;

fn cfg(dir: &TempDir, max: u64) -> ProducerConfig {
    ProducerConfig {
        spool_dir: dir.path().to_path_buf(),
        prefix: "events".into(),
        max_segment_bytes: max,
    }
}

#[test]
fn append_writes_line_and_fsyncs() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(cfg(&dir, 10_000)).unwrap();
    let off = p.append_line(b"{\"k\":1}").unwrap();
    assert_eq!(off.segment, "events-0.jsonl");
    assert_eq!(off.byte_offset, 8); // 7 bytes + 1 newline

    let path = dir.path().join("events-0.jsonl");
    let contents = fs::read(path).unwrap();
    assert_eq!(contents, b"{\"k\":1}\n");
}

#[test]
fn append_rolls_to_new_segment_at_cap() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(cfg(&dir, 10)).unwrap();
    let off1 = p.append_line(b"AAAAAA").unwrap(); // 7 bytes incl. \n
    let off2 = p.append_line(b"BBBBBB").unwrap(); // would push past 10
    assert_eq!(off1.segment, "events-0.jsonl");
    assert_eq!(off2.segment, "events-1.jsonl");
    assert_eq!(off2.byte_offset, 7);
}

#[test]
fn append_rejects_embedded_newline() {
    let dir = TempDir::new().unwrap();
    let mut p = Producer::open(cfg(&dir, 10_000)).unwrap();
    let err = p.append_line(b"a\nb").unwrap_err();
    assert!(matches!(err, ProducerError::EmbeddedNewline));
}

#[test]
fn open_recovers_truncated_last_line() {
    let dir = TempDir::new().unwrap();
    // Pre-seed a segment with one good line + one truncated tail.
    fs::write(dir.path().join("events-0.jsonl"), b"good\nbad-no-newline").unwrap();
    let mut p = Producer::open(cfg(&dir, 10_000)).unwrap();
    // After open, the file should be truncated back to "good\n".
    let contents = fs::read(dir.path().join("events-0.jsonl")).unwrap();
    assert_eq!(contents, b"good\n");
    // And the next append should follow at offset 5.
    let off = p.append_line(b"next").unwrap();
    assert_eq!(off.byte_offset, 10); // 5 + 5
}

#[test]
fn open_picks_highest_existing_segment() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("events-0.jsonl"), b"a\n").unwrap();
    fs::write(dir.path().join("events-3.jsonl"), b"b\n").unwrap();
    let mut p = Producer::open(cfg(&dir, 10_000)).unwrap();
    let off = p.append_line(b"c").unwrap();
    assert_eq!(off.segment, "events-3.jsonl");
    assert_eq!(off.byte_offset, 4);
}
