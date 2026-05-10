//! Spool consumer — tail-follow + checkpoint advance.
//!
//! Implementation lands in Task A1.3.

use thiserror::Error;

/// One record yielded by `Consumer::next`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// The raw JSONL line bytes (without the trailing `\n`).
    pub bytes: Vec<u8>,
    /// Durable position *after* this record. Pass to `Checkpoint::advance`
    /// once downstream durability is confirmed.
    pub offset: crate::DurableOffset,
}

/// Errors produced by the consumer.
#[derive(Debug, Error)]
pub enum ConsumerError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Truncated / malformed line found at the given absolute byte position.
    /// The consumer skips to the next `\n` and continues; callers can
    /// surface this for spec-§3.10 `spool_corruption` events.
    #[error("corruption at segment={segment} offset={byte_offset}: {bytes_skipped} bytes skipped")]
    Corruption {
        /// Segment basename.
        segment: String,
        /// Byte offset where corruption began.
        byte_offset: u64,
        /// Number of bytes skipped to reach the next `\n`.
        bytes_skipped: u64,
    },
}

/// Consumer (reader) for a single spool. One `Consumer` per checkpoint —
/// concurrent consumers must use distinct checkpoint files (spec §3.8.1
/// "Single in-flight ack" invariant is enforced by callers, not the library).
pub struct Consumer {}
