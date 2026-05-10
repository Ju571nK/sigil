//! Atomic checkpoint write (tmp + fsync + rename), single fsync barrier.
//!
//! Implementation lands in Task A1.3 (alongside Consumer).

use std::path::PathBuf;
use thiserror::Error;

/// Errors produced by checkpoint operations.
#[derive(Debug, Error)]
pub enum CheckpointError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization / deserialization failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Persistent checkpoint state for one consumer.
pub struct Checkpoint {
    _path: PathBuf,
}
