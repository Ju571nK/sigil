use andeda_core::event::*;
use andeda_core::sink::jsonl::JsonlSink;
use andeda_core::sink::EventSink;
use std::path::PathBuf;
use tempfile::TempDir;
use time::macros::datetime;

fn ev(ts: time::OffsetDateTime) -> Event {
    Event::new_file_change(
        ts,
        "h",
        PathBuf::from("/x"),
        Evidence::FileChange {
            change_kind: FileChangeKind::Modified,
            before_hash: None,
            after_hash: Some("a".into()),
            recheck_hash: None,
            rename_from: None,
            size_after: Some(1),
            evidence_quality: EvidenceQuality::Definitive,
        },
        Some("t".into()),
    )
}

#[test]
fn lazy_rotation_after_simulated_sleep() {
    let td = TempDir::new().unwrap();
    let mut sink = JsonlSink::open(td.path(), datetime!(2026-05-08 22:00 UTC)).unwrap();
    sink.write(&ev(datetime!(2026-05-08 22:00:01 UTC))).unwrap();
    let day1 = sink.current_file().to_path_buf();
    sink.write(&ev(datetime!(2026-05-10 09:00:00 UTC))).unwrap();
    let day3 = sink.current_file().to_path_buf();
    assert_ne!(day1, day3);
    assert!(day3.to_string_lossy().contains("2026-05-10"));
}
