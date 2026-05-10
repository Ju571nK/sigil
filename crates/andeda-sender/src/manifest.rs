//! In-memory batch manifest used by data_task to translate the server's
//! event_id-based ack into byte/sequence offsets.
//!
//! Spec §3.8.3 — manifest lives only for the in-flight batch.

use std::collections::HashMap;
use uuid::Uuid;

/// Byte range an event occupies inside the JSONL spool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

/// One manifest entry per event in the in-flight batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub event_id: Uuid,
    pub byte_range: ByteRange,
    pub provisional_sequence: u64,
    /// Filename the byte_range refers to.
    pub current_file: String,
}

#[derive(Default, Debug)]
pub struct BatchManifest {
    entries: Vec<ManifestEntry>,
    by_id: HashMap<Uuid, usize>,
}

impl BatchManifest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, entry: ManifestEntry) {
        let idx = self.entries.len();
        self.by_id.insert(entry.event_id, idx);
        self.entries.push(entry);
    }

    pub fn lookup(&self, event_id: &Uuid) -> Option<&ManifestEntry> {
        self.by_id.get(event_id).map(|i| &self.entries[*i])
    }

    pub fn last(&self) -> Option<&ManifestEntry> {
        self.entries.last()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ManifestEntry> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u128, seq: u64, start: u64, end: u64) -> ManifestEntry {
        ManifestEntry {
            event_id: Uuid::from_u128(id),
            byte_range: ByteRange { start, end },
            provisional_sequence: seq,
            current_file: "events-1.jsonl".into(),
        }
    }

    #[test]
    fn lookup_finds_pushed_entry() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 0, 100));
        m.push(entry(2, 11, 100, 200));
        let e = m.lookup(&Uuid::from_u128(2)).unwrap();
        assert_eq!(e.byte_range.end, 200);
        assert_eq!(e.provisional_sequence, 11);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 0, 100));
        assert!(m.lookup(&Uuid::from_u128(99)).is_none());
    }

    #[test]
    fn last_returns_last_pushed() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 0, 100));
        m.push(entry(2, 11, 100, 200));
        assert_eq!(m.last().unwrap().event_id, Uuid::from_u128(2));
    }

    #[test]
    fn empty_manifest_is_empty() {
        let m = BatchManifest::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }
}
