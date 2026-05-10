//! Data plane: builds batches, POSTs them, advances offset on ack.

use crate::manifest::BatchManifest;
use crate::state::SenderState;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AckError {
    #[error("server's high_water_event_id {0} not in batch manifest")]
    HighWaterUnknown(Uuid),
    #[error("manifest empty — should not happen for a non-empty batch")]
    EmptyManifest,
}

/// Given the server-provided `high_water_event_id`, compute the
/// `SenderState` that should be persisted after this batch is acked.
/// Spec §3.8.3 — high_water is the last event_id in the batch in
/// submission order, regardless of accept/reject.
pub fn apply_ack(
    manifest: &BatchManifest,
    high_water_event_id: Uuid,
) -> Result<SenderState, AckError> {
    if manifest.is_empty() {
        return Err(AckError::EmptyManifest);
    }
    let entry = manifest
        .lookup(&high_water_event_id)
        .ok_or(AckError::HighWaterUnknown(high_water_event_id))?;
    Ok(SenderState {
        current_file: entry.current_file.clone(),
        byte_offset: entry.byte_range.end,
        last_acked_sequence: entry.provisional_sequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ByteRange, ManifestEntry};

    fn entry(id: u128, seq: u64, end: u64) -> ManifestEntry {
        ManifestEntry {
            event_id: Uuid::from_u128(id),
            byte_range: ByteRange { start: end - 100, end },
            provisional_sequence: seq,
            current_file: "events-1.jsonl".into(),
        }
    }

    #[test]
    fn high_water_at_end_advances_to_last() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 100));
        m.push(entry(2, 11, 200));
        m.push(entry(3, 12, 300));
        let s = apply_ack(&m, Uuid::from_u128(3)).unwrap();
        assert_eq!(s.byte_offset, 300);
        assert_eq!(s.last_acked_sequence, 12);
    }

    #[test]
    fn high_water_in_middle_advances_to_middle() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 100));
        m.push(entry(2, 11, 200));
        m.push(entry(3, 12, 300));
        let s = apply_ack(&m, Uuid::from_u128(2)).unwrap();
        assert_eq!(s.byte_offset, 200);
        assert_eq!(s.last_acked_sequence, 11);
    }

    #[test]
    fn unknown_high_water_is_error() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 100));
        let err = apply_ack(&m, Uuid::from_u128(999)).unwrap_err();
        assert!(matches!(err, AckError::HighWaterUnknown(_)));
    }

    #[test]
    fn empty_manifest_is_error() {
        let m = BatchManifest::new();
        let err = apply_ack(&m, Uuid::from_u128(1)).unwrap_err();
        assert!(matches!(err, AckError::EmptyManifest));
    }
}
