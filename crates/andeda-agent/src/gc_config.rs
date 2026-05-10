//! GC thresholds for the agent's `events/` directory.
//!
//! Spec §3.9:
//! - Soft floor (10 GB / 72 h): GC normally; do NOT delete past sender offset.
//! - Hard ceiling (25 GB / 7 days): force GC; emit `agent_jsonl_force_gc`
//!   and `sender_skipped_segment` for any segment deleted past the sender.

use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcConfig {
    /// GC starts deleting fully-consumed segments only when total size exceeds this.
    pub soft_floor_bytes: u64,
    /// OR when the oldest segment is older than this (whichever fires first).
    pub soft_floor_age: Duration,
    /// Force GC past the sender offset when total size exceeds this.
    pub hard_ceiling_bytes: u64,
    /// OR when the oldest segment is older than this.
    pub hard_ceiling_age: Duration,
}

impl GcConfig {
    /// Spec defaults: soft 10 GB / 72 h, hard 25 GB / 7 days.
    pub fn defaults() -> Self {
        GcConfig {
            soft_floor_bytes: 10 * 1024 * 1024 * 1024,
            soft_floor_age: Duration::from_secs(72 * 60 * 60),
            hard_ceiling_bytes: 25 * 1024 * 1024 * 1024,
            hard_ceiling_age: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }

    /// Validate that the hard ceiling is strictly above the soft floor on
    /// both axes. Misconfigured ceilings would either prevent any forced GC
    /// (hard <= soft) or produce ambiguous trigger semantics.
    pub fn validate(&self) -> Result<(), GcConfigError> {
        if self.hard_ceiling_bytes <= self.soft_floor_bytes {
            return Err(GcConfigError::HardBytesNotAboveSoft {
                soft: self.soft_floor_bytes,
                hard: self.hard_ceiling_bytes,
            });
        }
        if self.hard_ceiling_age <= self.soft_floor_age {
            return Err(GcConfigError::HardAgeNotAboveSoft {
                soft_secs: self.soft_floor_age.as_secs(),
                hard_secs: self.hard_ceiling_age.as_secs(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum GcConfigError {
    /// Hard ceiling bytes must be > soft floor bytes.
    #[error("hard_ceiling_bytes ({hard}) must exceed soft_floor_bytes ({soft})")]
    HardBytesNotAboveSoft {
        /// Soft floor bytes.
        soft: u64,
        /// Hard ceiling bytes.
        hard: u64,
    },
    /// Hard ceiling age must be > soft floor age.
    #[error("hard_ceiling_age ({hard_secs}s) must exceed soft_floor_age ({soft_secs}s)")]
    HardAgeNotAboveSoft {
        /// Soft floor age in seconds.
        soft_secs: u64,
        /// Hard ceiling age in seconds.
        hard_secs: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_spec_locked() {
        let d = GcConfig::defaults();
        assert_eq!(d.soft_floor_bytes, 10 * 1024 * 1024 * 1024);
        assert_eq!(d.soft_floor_age.as_secs(), 72 * 60 * 60);
        assert_eq!(d.hard_ceiling_bytes, 25 * 1024 * 1024 * 1024);
        assert_eq!(d.hard_ceiling_age.as_secs(), 7 * 24 * 60 * 60);
    }

    #[test]
    fn defaults_validate() {
        GcConfig::defaults().validate().unwrap();
    }

    #[test]
    fn hard_must_be_strictly_above_soft_on_bytes() {
        let mut c = GcConfig::defaults();
        c.hard_ceiling_bytes = c.soft_floor_bytes;
        assert!(matches!(
            c.validate(),
            Err(GcConfigError::HardBytesNotAboveSoft { .. })
        ));
    }

    #[test]
    fn hard_must_be_strictly_above_soft_on_age() {
        let mut c = GcConfig::defaults();
        c.hard_ceiling_age = c.soft_floor_age;
        assert!(matches!(
            c.validate(),
            Err(GcConfigError::HardAgeNotAboveSoft { .. })
        ));
    }
}
