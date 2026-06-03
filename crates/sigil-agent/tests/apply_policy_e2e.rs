//! e2e: `apply_policy` → atomic write → state advance → event → expiry-aware.

use ed25519_dalek::{Signer, SigningKey};
use parking_lot::{Mutex, RwLock};
use rand_core::RngCore;
use sigil_agent::policy_apply::{apply, ApplyContext, ApplyOutcome};
use sigil_agent::policy_expiry_task::{evaluate_for_test, ExpiryTaskCtx};
use sigil_core::event::Evidence;
use sigil_core::policy::canonical::to_canonical_bytes;
use sigil_core::policy::pubkeys::{Keystore, KeystoreEntry};
use sigil_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use sigil_core::state::HashCache;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn apply_policy_writes_yaml_advances_version_emits_reloaded_and_no_expiry_yet() {
    let dir = tempdir().unwrap();
    let cache = Arc::new(Mutex::new(
        HashCache::open(&dir.path().join("state.db")).unwrap(),
    ));
    let now = OffsetDateTime::now_utc();

    // Keystore with one valid pubkey — use fill_bytes workaround (same as A6.3).
    let mut secret = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut secret);
    let sk = SigningKey::from_bytes(&secret);
    let pk_b64 = data_encoding::BASE64.encode(&sk.verifying_key().to_bytes());
    let keystore = Arc::new(Keystore {
        pubkeys: vec![KeystoreEntry {
            id: "k1".into(),
            ed25519_pubkey_b64: pk_b64,
            valid_from: now - time::Duration::days(30),
            valid_until: now + time::Duration::days(365),
        }],
    });

    let (event_tx, mut event_rx) = mpsc::channel(8);
    let (vtx, vrx) = watch::channel(0i64);
    let (rp_vtx, _rp_vrx) = watch::channel(0i64);
    let active_vu = Arc::new(RwLock::new(None::<OffsetDateTime>));
    let policy_path = dir.path().join("policy.yaml");
    let apply_ctx = ApplyContext {
        keystore,
        cache: cache.clone(),
        policy_yaml_path: policy_path.clone(),
        host_id: "test-host".into(),
        event_tx: event_tx.clone(),
        policy_version_tx: vtx.clone(),
        active_valid_until: active_vu.clone(),
        rule_packs_yaml_path: dir.path().join("rule-packs.yaml"),
        rule_packs_version_tx: rp_vtx,
    };

    // Sign + send a v1 envelope.
    let env = SignedEnvelope {
        policy_version: 1,
        policy_bytes_b64: data_encoding::BASE64.encode(b"version: 1\nrules: []\n"),
        valid_until: now + time::Duration::hours(24),
        issued_at: now,
    };
    let canonical = to_canonical_bytes(&env).unwrap();
    let sig = sk.sign(&canonical);
    let resp = SignedPolicyResponse {
        etag: blake3::hash(&canonical).to_hex().to_string(),
        signed_envelope: env,
        signature: data_encoding::BASE64.encode(&sig.to_bytes()),
        signing_pubkey_id: "k1".into(),
        applied_at: now,
    };

    let outcome = apply(&apply_ctx, &resp).await;
    assert_eq!(
        outcome,
        ApplyOutcome::Accepted {
            applied_policy_version: 1
        }
    );

    // policy.yaml.
    let bytes = std::fs::read(&policy_path).unwrap();
    assert_eq!(bytes, b"version: 1\nrules: []\n");

    // state.db.
    assert_eq!(
        cache
            .lock()
            .host_meta_get()
            .unwrap()
            .last_applied_policy_version,
        1
    );

    // PolicyReloaded event.
    let ev = event_rx.recv().await.unwrap();
    assert!(matches!(
        ev.event.evidence,
        Evidence::PolicyReloaded { policy_version: 1 }
    ));

    // Shared cell set.
    assert!(active_vu.read().is_some());

    // A subsequent expiry-task tick should NOT fire — envelope is still valid.
    let expired = Arc::new(RwLock::new(false));
    let exp_ctx = ExpiryTaskCtx {
        host_id: "test-host".into(),
        policy_expired_active: expired.clone(),
        active_valid_until: active_vu.clone(),
        policy_version_rx: vrx,
        event_tx,
        shutdown: CancellationToken::new(),
        tick: Duration::from_millis(10),
    };
    let mut last = None;
    evaluate_for_test(&exp_ctx, &mut last).await;
    assert!(!*expired.read());
    assert!(event_rx.try_recv().is_err());
    drop(vtx);
}
