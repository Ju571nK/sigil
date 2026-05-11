//! Server-of-record for the `apply_policy` IPC handler.
//!
//! Spec §4.4. The handler is pure orchestration:
//!   1. Run the A5 verifier.
//!   2. On Ok: atomic_write(policy.yaml, version) → notify watchers → ack.
//!   3. On Err with reason: emit PolicySignatureInvalid → reject ack.
//!   4. On Err::Internal: log + 5xx-equivalent (re-tries OK).

use parking_lot::{Mutex, RwLock};
use sigil_core::event::{
    Event, Evidence, PolicySignatureInvalidReason, Severity, SourceKind, Subject, AGENT_VERSION,
    SCHEMA_VERSION,
};
use sigil_core::policy::{
    atomic_write, pubkeys::Keystore, signed_envelope::SignedPolicyResponse, verify_envelope,
    AtomicWriteError, VerifyError,
};
use sigil_core::state::HashCache;
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::state_task::CommittableEvent;

/// Outcome the IPC handler returns to the sender.
#[derive(Debug, PartialEq)]
pub enum ApplyOutcome {
    /// Verifier accepted; disk + state.db advanced.
    Accepted { applied_policy_version: i64 },
    /// Verifier rejected; event emitted; nothing changed on disk or in state.db.
    Rejected {
        reason: PolicySignatureInvalidReason,
    },
    /// Internal failure (keystore I/O, disk write failure, etc.). Sender SHOULD
    /// retry. NO `PolicySignatureInvalid` event was emitted.
    Internal { detail: String },
}

/// Long-lived handle the runtime hands to the IPC handler.
pub struct ApplyContext {
    pub keystore: Arc<Keystore>,
    pub cache: Arc<Mutex<HashCache>>,
    pub policy_yaml_path: PathBuf,
    pub host_id: String,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    /// Broadcasts the new `last_applied_policy_version` whenever a
    /// successful apply commits. Receivers re-derive what they need.
    pub policy_version_tx: watch::Sender<i64>,
    /// Shared cell — written by `apply` on every successful commit, read
    /// by `policy_expiry_task` and the IPC `PolicyStatus` handler.
    pub active_valid_until: Arc<RwLock<Option<OffsetDateTime>>>,
}

/// Apply a freshly-received `SignedPolicyResponse`.
pub async fn apply(ctx: &ApplyContext, response: &SignedPolicyResponse) -> ApplyOutcome {
    let now = OffsetDateTime::now_utc();
    let last_applied = {
        let cache = ctx.cache.lock();
        match cache.host_meta_get() {
            Ok(m) => m.last_applied_policy_version,
            Err(e) => {
                return ApplyOutcome::Internal {
                    detail: format!("host_meta_get: {e}"),
                };
            }
        }
    };

    // Capture envelope's valid_until BEFORE the move into verify; we'll
    // publish it to `active_valid_until` only after the atomic write succeeds.
    let new_valid_until = response.signed_envelope.valid_until;

    let verified = match verify_envelope(&ctx.keystore, response, now, last_applied) {
        Ok(v) => v,
        Err(VerifyError::Internal(detail)) => {
            // Internal — do NOT emit PolicySignatureInvalid; sender retries.
            return ApplyOutcome::Internal { detail };
        }
        Err(other) => {
            let reason = other
                .reason()
                .expect("non-Internal verify error has a reason");
            emit_invalid(ctx, &reason, response, last_applied).await;
            return ApplyOutcome::Rejected { reason };
        }
    };

    // Verifier accepted — commit.
    let write_result = {
        let cache = ctx.cache.lock();
        atomic_write(
            &ctx.policy_yaml_path,
            &verified.policy_bytes,
            &cache,
            verified.policy_version,
        )
    };
    match write_result {
        Ok(()) => {
            // Update the shared cell so the expiry monitor + IPC PolicyStatus
            // can see the new envelope's valid_until.
            *ctx.active_valid_until.write() = Some(new_valid_until);
            // Notify subscribers (heartbeat, expiry monitor) that the
            // active policy version advanced. Send is best-effort; if no
            // receiver is alive we still consider apply successful.
            let _ = ctx.policy_version_tx.send(verified.policy_version);
            emit_reloaded(ctx, verified.policy_version).await;
            ApplyOutcome::Accepted {
                applied_policy_version: verified.policy_version,
            }
        }
        Err(AtomicWriteError::Io(e)) => ApplyOutcome::Internal {
            detail: format!("atomic disk write: {e}"),
        },
        Err(AtomicWriteError::StateAfterDisk(e)) => {
            // Disk is ahead of state.db. Surface as Internal so the sender
            // retries; reconciliation on next boot will fix the gap.
            ApplyOutcome::Internal {
                detail: format!("state-after-disk: {e}"),
            }
        }
    }
}

async fn emit_invalid(
    ctx: &ApplyContext,
    reason: &PolicySignatureInvalidReason,
    response: &SignedPolicyResponse,
    last_applied: i64,
) {
    let ev = Event {
        schema_version: SCHEMA_VERSION,
        event_id: Uuid::now_v7(),
        ts: OffsetDateTime::now_utc(),
        host_id: ctx.host_id.clone(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Warn,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence: Evidence::PolicySignatureInvalid {
            reason: *reason,
            signing_pubkey_id: response.signing_pubkey_id.clone(),
            policy_version_in_envelope: response.signed_envelope.policy_version,
            last_applied_policy_version: last_applied,
        },
        target_id: None,
    };
    let _ = ctx
        .event_tx
        .send(CommittableEvent {
            event: ev,
            new_hash: None,
            path_for_db: PathBuf::new(),
            target_id: String::new(),
        })
        .await;
}

async fn emit_reloaded(ctx: &ApplyContext, version: i64) {
    let ev = Event {
        schema_version: SCHEMA_VERSION,
        event_id: Uuid::now_v7(),
        ts: OffsetDateTime::now_utc(),
        host_id: ctx.host_id.clone(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Info,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence: Evidence::PolicyReloaded {
            policy_version: version,
        },
        target_id: None,
    };
    let _ = ctx
        .event_tx
        .send(CommittableEvent {
            event: ev,
            new_hash: None,
            path_for_db: PathBuf::new(),
            target_id: String::new(),
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::RngCore;
    use sigil_core::policy::canonical::to_canonical_bytes;
    use sigil_core::policy::pubkeys::KeystoreEntry;
    use sigil_core::policy::signed_envelope::SignedEnvelope;
    use tempfile::tempdir;
    use time::macros::datetime;

    struct Harness {
        ctx: ApplyContext,
        sk: SigningKey,
        rx_event: mpsc::Receiver<CommittableEvent>,
        rx_version: watch::Receiver<i64>,
        active_valid_until: Arc<RwLock<Option<OffsetDateTime>>>,
        _dir: tempfile::TempDir,
    }

    fn build_harness(now: OffsetDateTime, last_applied: i64) -> Harness {
        let dir = tempdir().unwrap();
        let cache = HashCache::open(&dir.path().join("state.db")).unwrap();
        cache.host_meta_set_policy_version(last_applied).unwrap();
        let cache = Arc::new(Mutex::new(cache));

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

        let (event_tx, rx_event) = mpsc::channel(16);
        let (policy_version_tx, rx_version) = watch::channel(last_applied);
        let active_valid_until = Arc::new(RwLock::new(None));

        Harness {
            ctx: ApplyContext {
                keystore,
                cache,
                policy_yaml_path: dir.path().join("policy.yaml"),
                host_id: "test-host".into(),
                event_tx,
                policy_version_tx,
                active_valid_until: active_valid_until.clone(),
            },
            sk,
            rx_event,
            rx_version,
            active_valid_until,
            _dir: dir,
        }
    }

    fn well_formed_envelope(version: i64, now: OffsetDateTime) -> SignedEnvelope {
        SignedEnvelope {
            policy_version: version,
            policy_bytes_b64: data_encoding::BASE64.encode(b"version: 1\nrules: []\n"),
            valid_until: now + time::Duration::hours(24),
            issued_at: now,
        }
    }

    fn sign(sk: &SigningKey, env: SignedEnvelope, now: OffsetDateTime) -> SignedPolicyResponse {
        let bytes = to_canonical_bytes(&env).unwrap();
        let sig = sk.sign(&bytes);
        SignedPolicyResponse {
            etag: blake3::hash(&bytes).to_hex().to_string(),
            signed_envelope: env,
            signature: data_encoding::BASE64.encode(&sig.to_bytes()),
            signing_pubkey_id: "k1".into(),
            applied_at: now,
        }
    }

    #[tokio::test]
    async fn happy_path_writes_yaml_advances_version_emits_reloaded() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let mut h = build_harness(now, 0);
        let envelope = well_formed_envelope(1, now);
        let expected_valid_until = envelope.valid_until;
        let resp = sign(&h.sk, envelope, now);

        let outcome = apply(&h.ctx, &resp).await;
        assert_eq!(
            outcome,
            ApplyOutcome::Accepted {
                applied_policy_version: 1
            }
        );

        // policy.yaml exists with the decoded bytes.
        let written = std::fs::read(&h.ctx.policy_yaml_path).unwrap();
        assert_eq!(written, b"version: 1\nrules: []\n");

        // state.db advanced.
        let v = h
            .ctx
            .cache
            .lock()
            .host_meta_get()
            .unwrap()
            .last_applied_policy_version;
        assert_eq!(v, 1);

        // active_valid_until cell mutated to the envelope's valid_until.
        assert_eq!(*h.active_valid_until.read(), Some(expected_valid_until));

        // PolicyReloaded event emitted.
        let ev = h.rx_event.recv().await.unwrap();
        assert!(matches!(
            ev.event.evidence,
            Evidence::PolicyReloaded { policy_version: 1 }
        ));

        // Watch channel updated.
        h.rx_version.changed().await.unwrap();
        assert_eq!(*h.rx_version.borrow(), 1);
    }

    #[tokio::test]
    async fn rejected_envelope_emits_invalid_does_not_touch_disk_or_state() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let mut h = build_harness(now, 5);
        // version 5 == last_applied 5 → version_regression
        let resp = sign(&h.sk, well_formed_envelope(5, now), now);

        let outcome = apply(&h.ctx, &resp).await;
        assert_eq!(
            outcome,
            ApplyOutcome::Rejected {
                reason: PolicySignatureInvalidReason::VersionRegression
            }
        );

        assert!(!h.ctx.policy_yaml_path.exists());
        let v = h
            .ctx
            .cache
            .lock()
            .host_meta_get()
            .unwrap()
            .last_applied_policy_version;
        assert_eq!(v, 5);

        // PolicySignatureInvalid event emitted.
        let ev = h.rx_event.recv().await.unwrap();
        match ev.event.evidence {
            Evidence::PolicySignatureInvalid { reason, .. } => {
                assert_eq!(reason, PolicySignatureInvalidReason::VersionRegression);
            }
            other => panic!("expected PolicySignatureInvalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pubkey_unknown_emits_invalid_with_correct_reason() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let mut h = build_harness(now, 0);
        let mut resp = sign(&h.sk, well_formed_envelope(1, now), now);
        resp.signing_pubkey_id = "k-unknown".into();

        let outcome = apply(&h.ctx, &resp).await;
        assert_eq!(
            outcome,
            ApplyOutcome::Rejected {
                reason: PolicySignatureInvalidReason::PubkeyUnknown
            }
        );

        let ev = h.rx_event.recv().await.unwrap();
        match ev.event.evidence {
            Evidence::PolicySignatureInvalid {
                reason: PolicySignatureInvalidReason::PubkeyUnknown,
                signing_pubkey_id,
                ..
            } => {
                assert_eq!(signing_pubkey_id, "k-unknown");
            }
            other => panic!("expected PubkeyUnknown PolicySignatureInvalid, got {other:?}"),
        }
    }
}
