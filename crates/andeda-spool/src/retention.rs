//! Producer-side retention: enforce `max_total_bytes` and `max_age` while
//! optionally respecting a consumer floor (spec §3.9 sender-aware GC).
//!
//! Implementation lands in Task A1.4.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::Duration;

/// Retention configuration for a single producer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Hard upper bound on total bytes across all segments. Beyond this, the
    /// oldest segments are deleted regardless of consumer position.
    pub max_total_bytes: u64,
    /// Hard upper bound on segment age. Beyond this, the segment is deleted
    /// regardless of consumer position.
    pub max_age: Duration,
}

/// Errors produced by retention operations.
#[derive(Debug, Error)]
pub enum RetentionError {
    /// I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Configuration violates `max_total_bytes > 0` or `max_age > 0`.
    #[error("invalid retention config: {0}")]
    InvalidConfig(String),
}

/// Retention enforcer for one spool directory.
pub struct Retention {}
