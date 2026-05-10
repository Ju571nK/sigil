//! Integration test: agent startup produces a host_id and reuses it.

use andeda_agent::host_meta_task::ensure_host_id;
use andeda_core::state::HashCache;
use tempfile::tempdir;

#[test]
fn startup_persists_and_reuses_host_id_across_two_opens() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("state.db");

    let id1 = {
        let cache = HashCache::open(&db).unwrap();
        ensure_host_id(&cache).unwrap()
    };
    let id2 = {
        let cache = HashCache::open(&db).unwrap();
        ensure_host_id(&cache).unwrap()
    };
    assert_eq!(id1, id2);
    // Sanity: was actually written to state.db (not just an in-memory cache).
    let cache = HashCache::open(&db).unwrap();
    let m = cache.host_meta_get().unwrap();
    assert_eq!(m.host_id.unwrap(), id1);
}
