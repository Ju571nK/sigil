//! Integration: a drift between two startups produces exactly one
//! `HostIdFingerprintDrift` event.

use andeda_agent::host_meta_task::{ensure_fingerprint, FingerprintOutcome};
use andeda_agent::platform::hw_fingerprint::HardwareFingerprint;
use andeda_core::state::HashCache;
use tempfile::tempdir;

struct Mock(String, String, String);
impl HardwareFingerprint for Mock {
    fn platform_uuid(&self) -> String { self.0.clone() }
    fn stable_mac(&self) -> String { self.1.clone() }
    fn cpu_brand(&self) -> String { self.2.clone() }
}

#[test]
fn drift_outcome_is_returned_exactly_once() {
    let dir = tempdir().unwrap();
    let cache = HashCache::open(&dir.path().join("state.db")).unwrap();

    // First boot: no drift (freshly persisted).
    let hw1 = Mock("A".into(), "B".into(), "C".into());
    let r1 = ensure_fingerprint(&cache, &hw1).unwrap();
    assert!(matches!(r1, FingerprintOutcome::FreshlyPersisted));

    // Second boot, same hardware: unchanged.
    let r2 = ensure_fingerprint(&cache, &hw1).unwrap();
    assert!(matches!(r2, FingerprintOutcome::Unchanged));

    // Third boot, hardware drifted: drift outcome.
    let hw2 = Mock("Z".into(), "B".into(), "C".into());
    let r3 = ensure_fingerprint(&cache, &hw2).unwrap();
    assert!(matches!(r3, FingerprintOutcome::Drift { .. }));

    // Fourth boot, same as third: unchanged (the drift was absorbed into state).
    let r4 = ensure_fingerprint(&cache, &hw2).unwrap();
    assert!(matches!(r4, FingerprintOutcome::Unchanged));
}
