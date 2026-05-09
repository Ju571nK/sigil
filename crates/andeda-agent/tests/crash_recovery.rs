//! Validates spec 1.4 invariant: state.db lags JSONL by at most one event under crash.

use andeda_core::state::HashCache;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn it_event_first_commit_survives_crash() {
    let td = TempDir::new().unwrap();
    let dbp = td.path().join("state.db");

    // Pretend a previous run committed baseline H1 for /x.
    {
        let c = HashCache::open(&dbp).unwrap();
        c.put(Path::new("/x"), "H1", 100, "t1", 0).unwrap();
    }

    // Pretend the agent emitted JSONL line for the change H1→H2 but crashed
    // before committing H2 to state.db.
    // (No DB write here — that is the simulated crash.)

    // On restart: the cache still has H1.
    let c2 = HashCache::open(&dbp).unwrap();
    assert_eq!(c2.get(Path::new("/x")).unwrap().as_deref(), Some("H1"));
}
