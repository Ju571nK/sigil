//! Property tests for crash-safety of the spool primitives.
//!
//! Spec §3.8.1: at-most-one-duplicate per crash point, no event loss.

use sigil_spool::{Checkpoint, Consumer, Producer, ProducerConfig};
use proptest::prelude::*;
use std::time::Duration;
use tempfile::TempDir;

fn pcfg(dir: &TempDir, max: u64) -> ProducerConfig {
    ProducerConfig {
        spool_dir: dir.path().to_path_buf(),
        prefix: "events".into(),
        max_segment_bytes: max,
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Property: every line written by the producer is read by the consumer
    /// in exactly the same order, no duplicates, no losses, when there are no
    /// crashes.
    #[test]
    fn no_loss_no_dup_no_reorder(
        lines in proptest::collection::vec("[a-z0-9]{1,32}", 1..200),
        cap in 16u64..256u64,
    ) {
        let dir = TempDir::new().unwrap();
        let mut p = Producer::open(pcfg(&dir, cap)).unwrap();
        for l in &lines {
            p.append_line(l.as_bytes()).unwrap();
        }
        drop(p);

        let mut cp = Checkpoint::open(dir.path().join("cp.json")).unwrap();
        let mut c = Consumer::open(dir.path(), "events", &mut cp).unwrap();
        let mut got: Vec<String> = Vec::new();
        while let Some(rec) = c.next_with_timeout(Duration::from_millis(50)).unwrap() {
            got.push(String::from_utf8(rec.bytes).unwrap());
        }
        prop_assert_eq!(got, lines);
    }

    /// Property: a consumer that drops AFTER reading but BEFORE advancing the
    /// checkpoint re-reads the last record (at-most-one duplicate per crash
    /// point). Spec §3.8.1.
    #[test]
    fn pre_advance_drop_yields_one_duplicate(
        lines in proptest::collection::vec("[a-z0-9]{1,16}", 2..30),
    ) {
        let dir = TempDir::new().unwrap();
        let mut p = Producer::open(pcfg(&dir, 1024)).unwrap();
        for l in &lines {
            p.append_line(l.as_bytes()).unwrap();
        }
        drop(p);

        // Read N-1 lines, advance checkpoint after each. Read the last one
        // and DROP without advancing.
        let cp_path = dir.path().join("cp.json");
        {
            let mut cp = Checkpoint::open(&cp_path).unwrap();
            let mut c = Consumer::open(dir.path(), "events", &mut cp).unwrap();
            for _ in 0..lines.len() - 1 {
                let r = c.next_with_timeout(Duration::from_millis(50)).unwrap().unwrap();
                cp.advance(r.offset).unwrap();
            }
            // Read the last one, but do NOT advance.
            let _ = c.next_with_timeout(Duration::from_millis(50)).unwrap().unwrap();
        }

        // Resume: should yield exactly the last line again, then nothing.
        let mut cp = Checkpoint::open(&cp_path).unwrap();
        let mut c = Consumer::open(dir.path(), "events", &mut cp).unwrap();
        let r = c.next_with_timeout(Duration::from_millis(50)).unwrap().unwrap();
        prop_assert_eq!(String::from_utf8(r.bytes).unwrap(), lines[lines.len() - 1].clone());
        let next = c.next_with_timeout(Duration::from_millis(50)).unwrap();
        prop_assert!(next.is_none());
    }

    /// Property: a producer truncated mid-write (last line incomplete) recovers
    /// on `Producer::open` without losing any complete prior line and without
    /// inventing new lines.
    #[test]
    fn truncation_recovery_preserves_complete_lines(
        good_lines in proptest::collection::vec("[a-z]{1,16}", 0..20),
        partial_tail in "[a-z]{0,32}",
    ) {
        let dir = TempDir::new().unwrap();
        // Write the good lines via the producer first.
        {
            let mut p = Producer::open(pcfg(&dir, 1024)).unwrap();
            for l in &good_lines {
                p.append_line(l.as_bytes()).unwrap();
            }
        }
        // Now manually corrupt by appending a tail without a trailing \n.
        if !partial_tail.is_empty() {
            use std::io::Write;
            let path = dir.path().join("events-0.jsonl");
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(partial_tail.as_bytes()).unwrap();
        }
        // Re-open: producer should truncate the partial tail.
        let _ = Producer::open(pcfg(&dir, 1024)).unwrap();

        // Read everything — should be exactly the good lines.
        let mut cp = Checkpoint::open(dir.path().join("cp.json")).unwrap();
        let mut c = Consumer::open(dir.path(), "events", &mut cp).unwrap();
        let mut got: Vec<String> = Vec::new();
        while let Some(rec) = c.next_with_timeout(Duration::from_millis(50)).unwrap() {
            got.push(String::from_utf8(rec.bytes).unwrap());
        }
        prop_assert_eq!(got, good_lines);
    }
}
