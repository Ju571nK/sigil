//! Phase 2 host_meta initialization (run once at agent startup).
//!
//! Spec §1.4 `host_id` persistence: on first start, generate a UUIDv4 and
//! store it in `state.db`. On subsequent starts, read the existing value.

use sigil_core::state::{HashCache, StateError};
use thiserror::Error;
use tracing::info;
use uuid::Uuid;

use crate::platform::hw_fingerprint::{compute, HardwareFingerprint};

/// Errors produced by host-meta initialization.
#[derive(Debug, Error)]
pub enum HostMetaInitError {
    /// Underlying state.db error.
    #[error("state: {0}")]
    State(#[from] StateError),
}

/// Initialize the `host_id` row if absent. Returns the resolved `host_id`.
pub fn ensure_host_id(cache: &HashCache) -> Result<String, HostMetaInitError> {
    let meta = cache.host_meta_get()?;
    if let Some(id) = meta.host_id {
        return Ok(id);
    }
    let new_id = Uuid::new_v4().to_string();
    cache.host_meta_set_host_id(&new_id)?;
    info!(host_id = %new_id, "generated new host_id (first run)");
    Ok(new_id)
}

/// Outcome of `ensure_fingerprint`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FingerprintOutcome {
    /// First run: fingerprint computed and persisted; no prior value.
    FreshlyPersisted,
    /// Subsequent run: fingerprint matches the persisted value.
    Unchanged,
    /// Subsequent run: fingerprint differs from persisted; spec §3.10
    /// `host_id_fingerprint_drift` event MUST be emitted by the caller
    /// with `prev` and `new`. State is updated to `new`.
    Drift {
        /// The previously-persisted fingerprint hex.
        prev: String,
        /// The freshly-computed fingerprint hex.
        new: String,
    },
}

/// Compute the hardware fingerprint and reconcile with the persisted value.
pub fn ensure_fingerprint<P: HardwareFingerprint>(
    cache: &HashCache,
    platform: &P,
) -> Result<FingerprintOutcome, HostMetaInitError> {
    let new = compute(platform);
    let prev_meta = cache.host_meta_get()?;
    match prev_meta.hw_fingerprint {
        None => {
            cache.host_meta_set_hw_fingerprint(&new)?;
            Ok(FingerprintOutcome::FreshlyPersisted)
        }
        Some(prev) if prev == new => Ok(FingerprintOutcome::Unchanged),
        Some(prev) => {
            cache.host_meta_set_hw_fingerprint(&new)?;
            Ok(FingerprintOutcome::Drift { prev, new })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn first_run_generates_and_persists_uuid() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        let cache = HashCache::open(&db).unwrap();
        let id = ensure_host_id(&cache).unwrap();
        // UUIDv4 string format: 8-4-4-4-12 hex digits
        assert_eq!(id.len(), 36);
        assert_eq!(id.matches('-').count(), 4);
        // Persisted.
        let again = ensure_host_id(&cache).unwrap();
        assert_eq!(id, again);
    }

    #[test]
    fn second_call_returns_same_id() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        let cache = HashCache::open(&db).unwrap();
        let id1 = ensure_host_id(&cache).unwrap();
        let id2 = ensure_host_id(&cache).unwrap();
        let id3 = ensure_host_id(&cache).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
    }

    #[test]
    fn distinct_state_dbs_get_distinct_host_ids() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let id1 = ensure_host_id(&HashCache::open(&dir1.path().join("state.db")).unwrap()).unwrap();
        let id2 = ensure_host_id(&HashCache::open(&dir2.path().join("state.db")).unwrap()).unwrap();
        assert_ne!(id1, id2);
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use crate::platform::hw_fingerprint::HardwareFingerprint;
    use tempfile::tempdir;

    struct Mock {
        pu: String,
        sm: String,
        cb: String,
    }
    impl HardwareFingerprint for Mock {
        fn platform_uuid(&self) -> String {
            self.pu.clone()
        }
        fn stable_mac(&self) -> String {
            self.sm.clone()
        }
        fn cpu_brand(&self) -> String {
            self.cb.clone()
        }
    }

    #[test]
    fn first_run_persists_fingerprint_and_returns_no_drift() {
        let dir = tempdir().unwrap();
        let cache = HashCache::open(&dir.path().join("state.db")).unwrap();
        let hw = Mock {
            pu: "A".into(),
            sm: "B".into(),
            cb: "C".into(),
        };
        let outcome = ensure_fingerprint(&cache, &hw).unwrap();
        assert_eq!(outcome, FingerprintOutcome::FreshlyPersisted);
        let m = cache.host_meta_get().unwrap();
        assert!(m.hw_fingerprint.is_some());
    }

    #[test]
    fn second_run_with_same_hw_returns_unchanged() {
        let dir = tempdir().unwrap();
        let cache = HashCache::open(&dir.path().join("state.db")).unwrap();
        let hw = Mock {
            pu: "A".into(),
            sm: "B".into(),
            cb: "C".into(),
        };
        let _ = ensure_fingerprint(&cache, &hw).unwrap();
        let outcome = ensure_fingerprint(&cache, &hw).unwrap();
        assert_eq!(outcome, FingerprintOutcome::Unchanged);
    }

    #[test]
    fn second_run_with_changed_hw_returns_drift_with_prev_and_new() {
        let dir = tempdir().unwrap();
        let cache = HashCache::open(&dir.path().join("state.db")).unwrap();
        let hw1 = Mock {
            pu: "A".into(),
            sm: "B".into(),
            cb: "C".into(),
        };
        let hw2 = Mock {
            pu: "Z".into(),
            sm: "B".into(),
            cb: "C".into(),
        };
        let _ = ensure_fingerprint(&cache, &hw1).unwrap();
        let outcome = ensure_fingerprint(&cache, &hw2).unwrap();
        match outcome {
            FingerprintOutcome::Drift { prev, new } => {
                assert_ne!(prev, new);
                assert_eq!(new.len(), 64);
            }
            _ => panic!("expected drift, got {outcome:?}"),
        }
        let m = cache.host_meta_get().unwrap();
        let new_fp = m.hw_fingerprint.unwrap();
        let expected = crate::platform::hw_fingerprint::compute(&hw2);
        assert_eq!(new_fp, expected);
    }
}
