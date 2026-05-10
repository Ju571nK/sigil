//! Spool producer — append + fsync + return durable offset.
//!
//! Implementation lands in Task A1.2.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

/// Configuration for a single producer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProducerConfig {
    /// Directory containing segment files.
    pub spool_dir: PathBuf,
    /// File name pattern; segment N is `<prefix>-<N>.jsonl`.
    pub prefix: String,
    /// Roll to a new segment when the current one exceeds this many bytes.
    pub max_segment_bytes: u64,
}

/// Errors produced by the producer.
#[derive(Debug, Error)]
pub enum ProducerError {
    /// I/O failure (read, write, fsync, rename).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The line passed to `append_line` contained a `\n` byte.
    #[error("line contains embedded newline")]
    EmbeddedNewline,
}

/// Producer (writer) for a single spool.
pub struct Producer {
    _cfg: ProducerConfig,
}
