use super::*;
use crate::policy::deployment::{ArtifactDescriptor, ArtifactKind};
use crate::policy::KeystoreEntry;
use ed25519_dalek::{Signer, SigningKey};
use std::cell::Cell;
use time::macros::datetime;

const POLICY: &[u8] = b"version: 1\ntargets: []\n";
const PACKS: &[u8] = b"version: 1\nrule_packs: []\n";

fn now() -> OffsetDateTime {
    datetime!(2026-09-23 0:00 UTC)
}

fn keys() -> Keystore {
    Keystore {
        pubkeys: vec![KeystoreEntry {
            id: "fixture-key".into(),
            ed25519_pubkey_b64: data_encoding::BASE64
                .encode(&SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
            valid_from: now() - time::Duration::days(1),
            valid_until: now() + time::Duration::days(2),
        }],
    }
}

fn signed(sequence: i64, policy: &[u8], packs: &[u8]) -> SignedDeploymentManifest {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/targeted-deployment-v2.json"
    ))
    .unwrap();
    let mut signed: SignedDeploymentManifest =
        serde_json::from_value(fixture["signed"].clone()).unwrap();
    signed.manifest.sequence = sequence;
    signed.manifest.policy = ArtifactDescriptor::from_bytes(ArtifactKind::Policy, policy).unwrap();
    signed.manifest.rule_packs =
        ArtifactDescriptor::from_bytes(ArtifactKind::RulePacks, packs).unwrap();
    signed.signature = data_encoding::BASE64.encode(
        &SigningKey::from_bytes(&[7; 32])
            .sign(&signed.manifest.signing_bytes().unwrap())
            .to_bytes(),
    );
    signed
}

fn commit(store: &mut DeploymentStore, sequence: i64) -> Result<i64, StoreError> {
    store.commit(
        &signed(sequence, POLICY, PACKS),
        POLICY,
        PACKS,
        &keys(),
        now,
        |verified, _, _| Ok(verified.manifest().sequence),
    )
}

fn current(store: &DeploymentStore) -> i64 {
    store
        .recover(&keys(), now(), |v, _, _| Ok(v.manifest().sequence))
        .unwrap()
        .unwrap()
}

#[test]
fn paired_commit_retry_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deployment.db");
    let mut store = DeploymentStore::initialize(&path, "host-a", 10, 20).unwrap();
    assert!(store
        .recover(&keys(), now(), |_, _, _| Ok(()))
        .unwrap()
        .is_none());
    assert!(commit(&mut store, 20).is_err());
    assert_eq!(commit(&mut store, 42).unwrap(), 42);
    assert_eq!(commit(&mut store, 42).unwrap(), 42);
    drop(store);
    let store = DeploymentStore::open_existing(&path, "host-a").unwrap();
    assert_eq!(current(&store), 42);
    let stored = read_snapshot(&store.conn, "host-a")
        .unwrap()
        .deployment
        .unwrap();
    assert_eq!(stored.policy, POLICY);
    assert_eq!(stored.rule_packs, PACKS);
    assert_eq!(
        store
            .conn
            .pragma_query_value(None, "synchronous", |r| r.get::<_, i32>(0))
            .unwrap(),
        2
    );
}

#[test]
fn missing_corrupt_or_changed_identity_does_not_reset_to_legacy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deployment.db");
    assert!(DeploymentStore::open_existing(&path, "host-a").is_err());
    assert!(!path.exists());
    let mut store = DeploymentStore::initialize(&path, "host-a", 0, 0).unwrap();
    assert!(DeploymentStore::initialize(&path, "host-a", 0, 0).is_err());
    assert!(DeploymentStore::open_existing(&path, "host-b").is_err());
    commit(&mut store, 42).unwrap();
    store
        .conn
        .execute("UPDATE deployment_state SET digest = 'corrupt'", [])
        .unwrap();
    assert!(DeploymentStore::open_existing(&path, "host-a").is_err());
    assert!(commit(&mut store, 43).is_err());
}

#[test]
fn corrupted_artifact_is_not_recovered_or_accepted_as_retry() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        DeploymentStore::initialize(&dir.path().join("deployment.db"), "host-a", 0, 0).unwrap();
    commit(&mut store, 42).unwrap();
    store
        .conn
        .execute("UPDATE deployment_state SET packs = x'00'", [])
        .unwrap();
    assert!(store.recover(&keys(), now(), |_, _, _| Ok(())).is_err());
    assert!(commit(&mut store, 42).is_err());
}

#[test]
fn malformed_stored_manifest_is_storage_corruption_not_request_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        DeploymentStore::initialize(&dir.path().join("deployment.db"), "host-a", 0, 0).unwrap();
    commit(&mut store, 42).unwrap();
    store
        .conn
        .execute("UPDATE deployment_state SET manifest = x'00'", [])
        .unwrap();
    assert!(matches!(
        commit(&mut store, 43),
        Err(StoreError::InvalidState)
    ));
}

#[test]
fn failure_in_either_artifact_or_preparation_preserves_last_good() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        DeploymentStore::initialize(&dir.path().join("deployment.db"), "host-a", 0, 0).unwrap();
    commit(&mut store, 42).unwrap();
    let bad = b"version: 99\n";
    assert!(store
        .commit(
            &signed(43, POLICY, bad),
            POLICY,
            bad,
            &keys(),
            now,
            |_, _, _| Ok(())
        )
        .is_err());
    assert!(store
        .commit(
            &signed(43, bad, PACKS),
            bad,
            PACKS,
            &keys(),
            now,
            |_, _, _| Ok(())
        )
        .is_err());
    let result: Result<(), _> = store.commit(
        &signed(43, POLICY, PACKS),
        POLICY,
        PACKS,
        &keys(),
        now,
        |_, _, _| Err("compile failed".into()),
    );
    assert!(matches!(result, Err(StoreError::Preparation(_))));
    assert_eq!(current(&store), 42);
}

#[test]
fn expiry_during_preparation_and_expired_recovery_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        DeploymentStore::initialize(&dir.path().join("deployment.db"), "host-a", 0, 0).unwrap();
    commit(&mut store, 42).unwrap();
    let clock = Cell::new(now());
    let result = store.commit(
        &signed(43, POLICY, PACKS),
        POLICY,
        PACKS,
        &keys(),
        || clock.get(),
        |_, _, _| {
            clock.set(now() + time::Duration::days(1));
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(StoreError::Verify(DeploymentError::Expired))
    ));
    assert_eq!(current(&store), 42);
    assert!(matches!(
        store.recover(&keys(), clock.get(), |_, _, _| Ok(())),
        Err(StoreError::Verify(DeploymentError::Expired))
    ));
}

#[test]
fn sqlite_write_failure_rolls_back_generation() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        DeploymentStore::initialize(&dir.path().join("deployment.db"), "host-a", 0, 0).unwrap();
    commit(&mut store, 42).unwrap();
    store.conn.execute_batch("CREATE TRIGGER reject_commit AFTER UPDATE ON deployment_state BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;").unwrap();
    assert!(matches!(commit(&mut store, 43), Err(StoreError::Sql(_))));
    assert_eq!(current(&store), 42);
}

#[test]
fn concurrent_connections_cannot_regress_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deployment.db");
    let mut store = DeploymentStore::initialize(&path, "host-a", 0, 0).unwrap();
    commit(&mut store, 42).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = [43, 44]
        .into_iter()
        .map(|sequence| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = DeploymentStore::open_existing(&path, "host-a").unwrap();
                barrier.wait();
                let result = commit(&mut store, sequence);
                if sequence == 44 {
                    assert!(result.is_ok());
                } else {
                    assert!(
                        result.is_ok()
                            || matches!(result, Err(StoreError::Verify(DeploymentError::Replay)))
                    );
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(current(&store), 44);
}

// Only the explicitly launched child sets these variables. Pause at actual
// commit boundaries so the parent kills without unwinding the transaction.
pub(super) fn crash_point(point: &str) {
    if std::env::var("SIGIL_DEPLOYMENT_CRASH_POINT")
        .ok()
        .as_deref()
        == Some(point)
    {
        let marker = std::env::var_os("SIGIL_DEPLOYMENT_CRASH_MARKER").unwrap();
        std::fs::write(marker, point).unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

#[test]
fn crash_worker() {
    let Some(path) = std::env::var_os("SIGIL_DEPLOYMENT_CRASH_DB") else {
        return;
    };
    let mut store = DeploymentStore::open_existing(Path::new(&path), "host-a").unwrap();
    let policy = b"version: 1\ntargets: []\n# next policy\n";
    let packs = b"version: 1\nrule_packs: []\n# next packs\n";
    store
        .commit(
            &signed(43, policy, packs),
            policy,
            packs,
            &keys(),
            now,
            |_, _, _| Ok(()),
        )
        .unwrap();
    panic!("child did not stop at crash point");
}

#[test]
fn process_crash_recovers_whole_old_or_new_generation() {
    for (point, expected) in [("before_commit", 42), ("after_commit", 43)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deployment.db");
        let marker = dir.path().join("paused");
        let mut store = DeploymentStore::initialize(&path, "host-a", 0, 0).unwrap();
        commit(&mut store, 42).unwrap();
        drop(store);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "policy::deployment_store::tests::crash_worker",
                "--nocapture",
            ])
            .env("SIGIL_DEPLOYMENT_CRASH_DB", &path)
            .env("SIGIL_DEPLOYMENT_CRASH_POINT", point)
            .env("SIGIL_DEPLOYMENT_CRASH_MARKER", &marker)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !marker.exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let reached = marker.exists();
        let _ = child.kill();
        child.wait().unwrap();
        assert!(reached, "child failed to reach {point}");
        let store = DeploymentStore::open_existing(&path, "host-a").unwrap();
        assert_eq!(current(&store), expected);
        let row = read_snapshot(&store.conn, "host-a")
            .unwrap()
            .deployment
            .unwrap();
        assert_eq!(row.policy.ends_with(b"# next policy\n"), expected == 43);
        assert_eq!(row.rule_packs.ends_with(b"# next packs\n"), expected == 43);
    }
}
