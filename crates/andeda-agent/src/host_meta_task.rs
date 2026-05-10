//! Phase 2 host_meta initialization (run once at agent startup).
//!
//! Spec §1.4 `host_id` persistence: on first start, generate a UUIDv4 and
//! store it in `state.db`. On subsequent starts, read the existing value.

use andeda_core::state::{HashCache, StateError};
use thiserror::Error;
use tracing::info;
use uuid::Uuid;

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
