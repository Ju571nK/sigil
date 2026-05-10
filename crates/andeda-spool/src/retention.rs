//! Producer-side retention: enforce `max_total_bytes` and `max_age` while
//! optionally respecting a consumer floor.

use crate::producer::ProducerConfig;
use crate::DurableOffset;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use thiserror::Error;
use time::Duration;

/// Retention configuration for a single producer.
///
/// **Serde caveat:** `time::Duration` serializes by default as a `(seconds,
/// nanoseconds)` tuple, which is awkward in human-edited YAML. Prefer building
/// these structs from typed config (e.g., a `humantime`-style string in YAML
/// that the loader converts to `Duration`) rather than serde-deserializing
/// directly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Hard upper bound on total bytes across all segments.
    pub max_total_bytes: u64,
    /// Hard upper bound on segment age.
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
///
/// **Concurrency:** Safe to run concurrently with the owning `Producer`; spool
/// segments are append-only and the highest-N (current) segment is never
/// touched. There is one race window: the producer may roll mid-enumeration,
/// in which case the formerly-highest segment becomes eligible on the next
/// cycle (still safe — just delayed). No advisory lock is held; do NOT run
/// two `Retention` enforcers against the same directory at the same time.
pub struct Retention {
    cfg: RetentionConfig,
}

impl Retention {
    /// Validate the config and construct an enforcer.
    pub fn new(cfg: RetentionConfig) -> Result<Self, RetentionError> {
        if cfg.max_total_bytes == 0 {
            return Err(RetentionError::InvalidConfig(
                "max_total_bytes must be > 0".into(),
            ));
        }
        if cfg.max_age <= Duration::ZERO {
            return Err(RetentionError::InvalidConfig(
                "max_age must be > 0".into(),
            ));
        }
        Ok(Self { cfg })
    }

    /// Soft enforcement: delete segments that are (a) entirely below the
    /// consumer floor (when given), AND (b) either over total-bytes cap or
    /// over max-age. Returns the basenames of removed segments.
    pub fn enforce(
        &self,
        pcfg: &ProducerConfig,
        consumer_floor: Option<&DurableOffset>,
    ) -> Result<Vec<String>, RetentionError> {
        let mut segs = list_segments(pcfg)?;
        if segs.is_empty() {
            return Ok(Vec::new());
        }
        // Never delete the current (highest-N) segment.
        segs.sort_by_key(|s| s.n);
        let highest_n = segs.last().unwrap().n;
        let floor_n = consumer_floor.map(|f| parse_n(&f.segment, &pcfg.prefix));

        let total: u64 = segs.iter().map(|s| s.size).sum();
        let now = SystemTime::now();
        // Convert max_age to a std::time::Duration for full nanosecond precision.
        let max_age_std = std::time::Duration::new(
            self.cfg.max_age.whole_seconds().max(0) as u64,
            self.cfg.max_age.subsec_nanoseconds().unsigned_abs(),
        );

        let mut removed = Vec::new();
        let mut running_total = total;
        for seg in segs.iter() {
            if seg.n == highest_n {
                continue;
            }
            // Respect consumer floor: only segments strictly below floor_n are
            // eligible (so a consumer pinned at segment N never loses N or above).
            if let Some(floor) = floor_n {
                if seg.n >= floor {
                    continue;
                }
            }
            let age = match now.duration_since(seg.modified) {
                Ok(d) => d,
                Err(_) => std::time::Duration::ZERO,
            };
            let over_size = running_total > self.cfg.max_total_bytes;
            let over_age = age > max_age_std;
            if over_size || over_age {
                fs::remove_file(&seg.path)?;
                removed.push(seg.basename.clone());
                running_total = running_total.saturating_sub(seg.size);
            }
        }
        Ok(removed)
    }

    /// Force GC: delete the oldest segments to bring total bytes within the
    /// configured cap, EVEN IF they are at or above the consumer floor.
    /// Returns the basenames of segments deleted past the floor — callers use
    /// this to emit the §3.10 `agent_jsonl_force_gc` event.
    pub fn force_gc(
        &self,
        pcfg: &ProducerConfig,
        consumer_floor: Option<&DurableOffset>,
    ) -> Result<Vec<String>, RetentionError> {
        let mut segs = list_segments(pcfg)?;
        if segs.is_empty() {
            return Ok(Vec::new());
        }
        segs.sort_by_key(|s| s.n);
        let highest_n = segs.last().unwrap().n;
        let total: u64 = segs.iter().map(|s| s.size).sum();
        if total <= self.cfg.max_total_bytes {
            return Ok(Vec::new());
        }
        let floor_n = consumer_floor.map(|f| parse_n(&f.segment, &pcfg.prefix));

        let mut forced_above_floor = Vec::new();
        let mut running_total = total;
        for seg in segs.iter() {
            if seg.n == highest_n {
                continue;
            }
            if running_total <= self.cfg.max_total_bytes {
                break;
            }
            let above_floor = floor_n.is_some_and(|floor| seg.n >= floor);
            fs::remove_file(&seg.path)?;
            running_total = running_total.saturating_sub(seg.size);
            if above_floor {
                forced_above_floor.push(seg.basename.clone());
            }
        }
        Ok(forced_above_floor)
    }
}

struct SegInfo {
    n: u64,
    basename: String,
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

fn list_segments(pcfg: &ProducerConfig) -> Result<Vec<SegInfo>, RetentionError> {
    let mut out = Vec::new();
    for entry in fs::read_dir(&pcfg.spool_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let n = match name
            .strip_prefix(&format!("{}-", pcfg.prefix))
            .and_then(|s| s.strip_suffix(".jsonl"))
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(n) => n,
            None => continue,
        };
        let meta = entry.metadata()?;
        out.push(SegInfo {
            n,
            basename: name,
            path: entry.path(),
            size: meta.len(),
            modified: meta.modified()?,
        });
    }
    Ok(out)
}

fn parse_n(basename: &str, prefix: &str) -> u64 {
    basename
        .strip_prefix(&format!("{prefix}-"))
        .and_then(|s| s.strip_suffix(".jsonl"))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}
