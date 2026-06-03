//! `host_meta` accessor over the singleton `state.db` row.
//!
//! Spec §1.4 host_id persistence + §3.8.2 last_applied_policy_version.

use crate::state::{HashCache, StateError};

/// Snapshot of the host_meta row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostMeta {
    /// UUIDv4 string, generated on first run, stable across restarts.
    pub host_id: Option<String>,
    /// blake3 hex of (platform_uuid || stable_mac || cpu_brand).
    pub hw_fingerprint: Option<String>,
    /// Per-customer monotonic counter. Defaults to 0 on a fresh state.db.
    pub last_applied_policy_version: i64,
    /// Per-customer monotonic counter for the applied rule-packs bundle.
    /// Defaults to 0 on a fresh state.db.
    pub last_applied_rule_packs_version: i64,
}

impl HashCache {
    /// Read the current host_meta row.
    pub fn host_meta_get(&self) -> Result<HostMeta, StateError> {
        let row = self.conn.query_row(
            "SELECT host_id, hw_fingerprint, last_applied_policy_version,
                    last_applied_rule_packs_version
             FROM host_meta WHERE id = 1",
            [],
            |r| {
                Ok(HostMeta {
                    host_id: r.get(0)?,
                    hw_fingerprint: r.get(1)?,
                    last_applied_policy_version: r.get(2)?,
                    last_applied_rule_packs_version: r.get(3)?,
                })
            },
        )?;
        Ok(row)
    }

    /// Set `host_id` (idempotent).
    pub fn host_meta_set_host_id(&self, host_id: &str) -> Result<(), StateError> {
        self.conn.execute(
            "UPDATE host_meta SET host_id = ?1 WHERE id = 1",
            rusqlite::params![host_id],
        )?;
        Ok(())
    }

    /// Set `hw_fingerprint` (idempotent).
    pub fn host_meta_set_hw_fingerprint(&self, fp: &str) -> Result<(), StateError> {
        self.conn.execute(
            "UPDATE host_meta SET hw_fingerprint = ?1 WHERE id = 1",
            rusqlite::params![fp],
        )?;
        Ok(())
    }

    /// Set `last_applied_policy_version` (called from the apply_policy IPC
    /// path after a verified envelope is durably written). Caller must ensure
    /// the new value is strictly greater than the current value (the §3.8.2
    /// monotonic check); this method does not enforce it because the agent's
    /// verify-chain already does so before commit.
    pub fn host_meta_set_policy_version(&self, version: i64) -> Result<(), StateError> {
        self.conn.execute(
            "UPDATE host_meta SET last_applied_policy_version = ?1 WHERE id = 1",
            rusqlite::params![version],
        )?;
        Ok(())
    }

    /// Set `last_applied_rule_packs_version` (advanced after a verified
    /// rule-packs bundle is durably written). Mirrors
    /// `host_meta_set_policy_version`; the monotonic check is enforced by the
    /// caller's verify-chain, not here.
    pub fn set_last_applied_rule_packs_version(&self, version: i64) -> Result<(), StateError> {
        self.conn.execute(
            "UPDATE host_meta SET last_applied_rule_packs_version = ?1 WHERE id = 1",
            rusqlite::params![version],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_cache() -> (tempfile::TempDir, HashCache) {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        let cache = HashCache::open(&db).unwrap();
        (dir, cache)
    }

    #[test]
    fn fresh_state_returns_empty_meta() {
        let (_dir, cache) = fresh_cache();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(m.host_id, None);
        assert_eq!(m.hw_fingerprint, None);
        assert_eq!(m.last_applied_policy_version, 0);
    }

    #[test]
    fn set_and_get_host_id() {
        let (_dir, cache) = fresh_cache();
        cache
            .host_meta_set_host_id("5a7c3e91-aaaa-bbbb-cccc-dddddddddddd")
            .unwrap();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(
            m.host_id.as_deref(),
            Some("5a7c3e91-aaaa-bbbb-cccc-dddddddddddd")
        );
    }

    #[test]
    fn set_and_get_hw_fingerprint() {
        let (_dir, cache) = fresh_cache();
        cache.host_meta_set_hw_fingerprint("deadbeef").unwrap();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(m.hw_fingerprint.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn set_and_get_policy_version() {
        let (_dir, cache) = fresh_cache();
        cache.host_meta_set_policy_version(42).unwrap();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(m.last_applied_policy_version, 42);
    }

    #[test]
    fn rule_packs_version_round_trips_and_column_exists() {
        let (_dir, c) = fresh_cache();
        assert_eq!(
            c.host_meta_get().unwrap().last_applied_rule_packs_version,
            0
        );
        c.set_last_applied_rule_packs_version(7).unwrap();
        assert_eq!(
            c.host_meta_get().unwrap().last_applied_rule_packs_version,
            7
        );
    }

    #[test]
    fn updates_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("state.db");
        {
            let cache = HashCache::open(&db).unwrap();
            cache.host_meta_set_host_id("persist-me").unwrap();
            cache.host_meta_set_policy_version(7).unwrap();
        }
        let cache = HashCache::open(&db).unwrap();
        let m = cache.host_meta_get().unwrap();
        assert_eq!(m.host_id.as_deref(), Some("persist-me"));
        assert_eq!(m.last_applied_policy_version, 7);
    }
}
