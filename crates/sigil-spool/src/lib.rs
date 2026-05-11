//! `andeda-spool` — shared JSONL = IPC primitive used at every Phase 2 hop.
//!
//! See spec §3.8.1 "Shared invariants of the JSONL=IPC pattern" for the
//! durability and recovery contract this crate enforces.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod checkpoint;
pub mod consumer;
pub mod producer;
pub mod retention;

pub use checkpoint::{Checkpoint, CheckpointError};
pub use consumer::{Consumer, ConsumerError, Record};
pub use producer::{Producer, ProducerConfig, ProducerError};
pub use retention::{Retention, RetentionConfig, RetentionError};

/// Durable position in a spool segment, returned by `Producer::append_line`
/// and consumed by `Checkpoint::advance`.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DurableOffset {
    /// Segment file name (basename, no directory).
    pub segment: String,
    /// Byte offset *after* the most recently written or read line.
    pub byte_offset: u64,
}
