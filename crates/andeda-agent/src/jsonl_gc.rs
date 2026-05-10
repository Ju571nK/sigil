//! Sender-aware JSONL GC decision engine.
//!
//! Spec §3.9. PURE function — no I/O, no event emit, no file deletion.
//! Caller wraps with disk listing + deletion + event emission.

use crate::gc_config::GcConfig;
use crate::sender_offset::SenderOffset;
use std::path::PathBuf;
use std::time::Duration;
use time::OffsetDateTime;

/// One discovered segment. Caller obtains these by listing `events_dir`
/// and `stat()`-ing each `events-YYYY-MM-DD*.jsonl` file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Segment {
    /// Filename only (e.g. `events-2026-05-15-002.jsonl`). Used for ordering.
    pub filename: String,
    /// Full path on disk — passed back so the caller can `unlink` it.
    pub path: PathBuf,
    /// Size in bytes from `stat()`.
    pub size_bytes: u64,
    /// File mtime — used for the "oldest segment" age threshold.
    pub mtime: OffsetDateTime,
}

/// Decision returned to the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcDecision {
    /// Segments to delete (oldest first). Caller `unlink`s each.
    pub to_delete: Vec<PathBuf>,
    /// Of `to_delete`, count that are PAST the sender offset (force-deleted).
    /// Triggers the `sender_skipped_segment` event when > 0.
    pub force_deleted_past_sender: usize,
    /// `true` when this cycle was triggered by the hard ceiling (size or age).
    /// Triggers the `agent_jsonl_force_gc` event.
    pub hard_ceiling_fired: bool,
    /// `true` if total size or oldest age is above the SOFT floor (regardless
    /// of whether deletion happened). Surfaced into the heartbeat field
    /// `jsonl_above_soft_floor`.
    pub above_soft_floor: bool,
}

/// Decide what to delete. The current segment (the one the sink is
/// actively writing to) is identified by `current_segment_filename` and
/// is NEVER eligible for deletion in the same cycle (the sink would
/// re-create it on the next write — we'd only churn).
pub fn decide(
    segments: &[Segment],
    sender_offset: Option<&SenderOffset>,
    current_segment_filename: &str,
    cfg: &GcConfig,
    now: OffsetDateTime,
) -> GcDecision {
    if segments.is_empty() {
        return GcDecision {
            to_delete: vec![],
            force_deleted_past_sender: 0,
            hard_ceiling_fired: false,
            above_soft_floor: false,
        };
    }

    // Sort oldest-first by filename. Filename embeds the date + seq, so
    // lexicographic order is chronological for `events-YYYY-MM-DD-NNN.jsonl`.
    let mut sorted: Vec<&Segment> = segments.iter().collect();
    sorted.sort_by(|a, b| a.filename.cmp(&b.filename));

    let total_size: u64 = sorted.iter().map(|s| s.size_bytes).sum();
    let oldest_age = sorted
        .first()
        .map(|s| (now - s.mtime).whole_seconds().max(0) as u64)
        .map(Duration::from_secs)
        .unwrap_or_default();

    let above_soft_bytes = total_size > cfg.soft_floor_bytes;
    let above_soft_age = oldest_age > cfg.soft_floor_age;
    let above_soft = above_soft_bytes || above_soft_age;

    let above_hard_bytes = total_size > cfg.hard_ceiling_bytes;
    let above_hard_age = oldest_age > cfg.hard_ceiling_age;
    let above_hard = above_hard_bytes || above_hard_age;

    if !above_soft {
        // Below soft floor — do nothing.
        return GcDecision {
            to_delete: vec![],
            force_deleted_past_sender: 0,
            hard_ceiling_fired: false,
            above_soft_floor: false,
        };
    }

    // Walk segments oldest → newest, deleting until we drop below the soft
    // floor. NEVER delete the current segment.
    let mut to_delete = Vec::new();
    let mut forced = 0usize;
    let mut running_size = total_size;
    let sender_seg = sender_offset.map(|o| o.current_segment.as_str());

    for s in &sorted {
        if s.filename == current_segment_filename {
            continue;
        }
        // Determine if this segment is past the sender. With no sender
        // record, treat ALL segments as not-yet-consumed.
        let past_sender = match sender_seg {
            Some(curr) => s.filename.as_str() < curr,
            None => false,
        };

        if !past_sender && !above_hard {
            // Soft-only mode: cannot touch unconsumed segments. Stop.
            break;
        }

        // Eligible to delete.
        to_delete.push(s.path.clone());
        running_size = running_size.saturating_sub(s.size_bytes);
        if !past_sender {
            forced += 1;
        }

        // Once we've dropped below the SOFT floor on bytes AND we're not
        // tripping the age threshold any more, stop.
        let still_above_bytes = running_size > cfg.soft_floor_bytes;
        // Age threshold cannot be relieved by deletion alone (next-oldest's
        // mtime is what counts), but we re-check.
        let next_oldest_age = sorted
            .get(to_delete.len())
            .map(|s| (now - s.mtime).whole_seconds().max(0) as u64)
            .map(Duration::from_secs)
            .unwrap_or_default();
        let still_above_age = next_oldest_age > cfg.soft_floor_age;
        if !still_above_bytes && !still_above_age {
            break;
        }
    }

    GcDecision {
        to_delete,
        force_deleted_past_sender: forced,
        hard_ceiling_fired: above_hard,
        above_soft_floor: above_soft,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use time::macros::datetime;

    fn seg(filename: &str, size: u64, mtime: OffsetDateTime) -> Segment {
        Segment {
            filename: filename.into(),
            path: PathBuf::from("/tmp/events").join(filename),
            size_bytes: size,
            mtime,
        }
    }

    fn cfg() -> GcConfig {
        GcConfig {
            soft_floor_bytes: 100,
            soft_floor_age: Duration::from_secs(3600),
            hard_ceiling_bytes: 1000,
            hard_ceiling_age: Duration::from_secs(7200),
        }
    }

    #[test]
    fn empty_dir_returns_no_op_decision() {
        let now = datetime!(2026-05-15 12:00 UTC);
        let d = decide(&[], None, "events-2026-05-15.jsonl", &cfg(), now);
        assert_eq!(d.to_delete, Vec::<PathBuf>::new());
        assert!(!d.above_soft_floor);
        assert!(!d.hard_ceiling_fired);
        assert_eq!(d.force_deleted_past_sender, 0);
    }

    #[test]
    fn under_soft_floor_deletes_nothing() {
        let now = datetime!(2026-05-15 12:00 UTC);
        let segs = vec![
            seg("events-2026-05-15.jsonl", 50, now - Duration::from_secs(60)),
        ];
        let d = decide(&segs, None, "events-2026-05-15.jsonl", &cfg(), now);
        assert!(d.to_delete.is_empty());
        assert!(!d.above_soft_floor);
    }

    #[test]
    fn above_soft_floor_no_sender_record_does_not_force_delete() {
        let now = datetime!(2026-05-15 12:00 UTC);
        let segs = vec![
            seg("events-2026-05-13.jsonl", 80, now - Duration::from_secs(60)),
            seg("events-2026-05-15.jsonl", 80, now - Duration::from_secs(60)),
        ];
        // total = 160 > soft floor (100) but NOT > hard ceiling (1000),
        // and there is no sender record → cannot delete anything.
        let d = decide(&segs, None, "events-2026-05-15.jsonl", &cfg(), now);
        assert!(d.above_soft_floor);
        assert!(!d.hard_ceiling_fired);
        assert!(d.to_delete.is_empty());
        assert_eq!(d.force_deleted_past_sender, 0);
    }

    #[test]
    fn above_soft_floor_with_sender_deletes_consumed_segments_only() {
        let now = datetime!(2026-05-15 12:00 UTC);
        let segs = vec![
            seg("events-2026-05-13.jsonl", 80, now - Duration::from_secs(60)),
            seg("events-2026-05-14.jsonl", 80, now - Duration::from_secs(60)),
            seg("events-2026-05-15.jsonl", 80, now - Duration::from_secs(60)),
        ];
        let off = SenderOffset {
            current_segment: "events-2026-05-15.jsonl".into(),
            byte_offset: 0,
            updated_at: now,
        };
        let d = decide(&segs, Some(&off), "events-2026-05-15.jsonl", &cfg(), now);
        // total = 240 > soft (100); both 05-13 and 05-14 are < 05-15 (the sender),
        // so they ARE delete-eligible. Deleting just 05-13 brings size to 160,
        // still above soft (100); also delete 05-14 → 80, below soft → stop.
        assert_eq!(d.to_delete.len(), 2);
        assert!(d.to_delete[0].to_string_lossy().contains("05-13"));
        assert!(d.to_delete[1].to_string_lossy().contains("05-14"));
        assert_eq!(d.force_deleted_past_sender, 0);
        assert!(!d.hard_ceiling_fired);
    }

    #[test]
    fn above_hard_ceiling_force_deletes_past_sender() {
        let now = datetime!(2026-05-15 12:00 UTC);
        let segs = vec![
            seg("events-2026-05-13.jsonl", 600, now - Duration::from_secs(60)),
            seg("events-2026-05-14.jsonl", 600, now - Duration::from_secs(60)),
        ];
        // total = 1200 > hard (1000). Sender is still on 05-13 (none consumed).
        let off = SenderOffset {
            current_segment: "events-2026-05-13.jsonl".into(),
            byte_offset: 100,
            updated_at: now,
        };
        let d = decide(&segs, Some(&off), "events-2026-05-14.jsonl", &cfg(), now);
        assert!(d.hard_ceiling_fired);
        // 05-13 is NOT past sender (sender's current is 05-13). Force-delete it.
        // After deletion: total = 600, below soft (100)? No, 600 > 100 still.
        // But the only other segment is the current segment (05-14) — never delete.
        assert_eq!(d.to_delete.len(), 1);
        assert_eq!(d.force_deleted_past_sender, 1);
    }

    #[test]
    fn above_hard_age_force_deletes_old_segments() {
        let now = datetime!(2026-05-15 12:00 UTC);
        let segs = vec![
            // ~3 hours old → above hard age (2h).
            seg("events-2026-05-15-001.jsonl", 50, now - Duration::from_secs(3 * 3600)),
            seg("events-2026-05-15-002.jsonl", 50, now - Duration::from_secs(60)),
        ];
        let off = SenderOffset {
            current_segment: "events-2026-05-15-001.jsonl".into(),
            byte_offset: 10,
            updated_at: now,
        };
        let d = decide(&segs, Some(&off), "events-2026-05-15-002.jsonl", &cfg(), now);
        assert!(d.hard_ceiling_fired);
        assert_eq!(d.to_delete.len(), 1);
        assert_eq!(d.force_deleted_past_sender, 1);
    }

    #[test]
    fn never_deletes_the_current_segment_even_when_above_hard() {
        let now = datetime!(2026-05-15 12:00 UTC);
        let segs = vec![seg("events-2026-05-15.jsonl", 5000, now)];
        let d = decide(&segs, None, "events-2026-05-15.jsonl", &cfg(), now);
        assert!(d.hard_ceiling_fired);
        assert!(d.to_delete.is_empty());
    }
}
