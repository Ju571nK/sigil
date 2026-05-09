use andeda_core::debounce::Debouncer;
use andeda_core::event::FileChangeKind;
use std::path::PathBuf;

#[test]
fn it_renamed_pair_within_window_via_debouncer() {
    // Renamed has 50 ms standard window. Two Renamed events for the same path
    // within 50 ms collapse to one BestEffort event.
    let mut d = Debouncer::new();
    d.push(PathBuf::from("/x"), FileChangeKind::Renamed, false, 0);
    d.push(PathBuf::from("/x"), FileChangeKind::Renamed, false, 30);
    let due = d.drain_due(80);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].coalesced_count, 2);
}
