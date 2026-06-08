//! e2e: a successful `apply_policy` makes the running agent pick up the new
//! policy's watch targets without a restart.
//!
//! Unix only — the test drives the agent's control socket (UDS) via
//! `TestAgent::apply_policy`, which isn't implemented for the Windows named pipe.
#![cfg(unix)]

mod common;
use common::{policy_for_paths, TestAgentBuilder};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::RngCore;
use sigil_core::policy::canonical::to_canonical_bytes;
use sigil_core::policy::pubkeys::{Keystore, KeystoreEntry};
use sigil_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use std::time::Duration;
use time::OffsetDateTime;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_policy_reloads_live_watch_targets() {
    let dir_x = tempfile::tempdir().unwrap();
    let dir_y = tempfile::tempdir().unwrap();
    let file_x = dir_x.path().join("x.json");
    let file_y = dir_y.path().join("y.json");

    // A signing key + a one-entry keystore the agent will load and verify against.
    let mut secret = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut secret);
    let sk = SigningKey::from_bytes(&secret);
    let now = OffsetDateTime::now_utc();
    let keystore = Keystore {
        pubkeys: vec![KeystoreEntry {
            id: "k1".into(),
            ed25519_pubkey_b64: data_encoding::BASE64.encode(&sk.verifying_key().to_bytes()),
            valid_from: now - time::Duration::days(1),
            valid_until: now + time::Duration::days(365),
        }],
    };
    let keystore_json = serde_json::to_vec(&keystore).unwrap();

    // Start on policy A (watch file X).
    let policy_a = policy_for_paths(&[file_x.to_str().unwrap()], "standard");
    let agent = TestAgentBuilder::new()
        .policy(&policy_a)
        .keystore_json(keystore_json)
        .start()
        .await;

    // Sanity: writing X produces a file_change under policy A. Re-write X until
    // one lands — a single write can fall in the watcher's startup gap (FSEvents
    // delivers from "now", no replay) and be lost under parallel load (#108),
    // mirroring the live-reload retry loop used for Y below.
    let is_x_change = |v: &serde_json::Value| {
        v["evidence"]["kind"] == "file_change"
            && v["subject"]["value"]
                .as_str()
                .map(|p| p.ends_with("x.json"))
                .unwrap_or(false)
    };
    let mut ev_x = None;
    for i in 0..60 {
        std::fs::write(&file_x, format!("x{i}").as_bytes()).unwrap();
        if let Some(ev) = agent
            .wait_for_event(&is_x_change, Duration::from_millis(250))
            .await
        {
            ev_x = Some(ev);
            break;
        }
    }
    let ev = ev_x.expect("policy A: file_change for X");
    assert_eq!(ev["schema_version"], 1);

    // Apply policy B (watch file Y instead) over the real control IPC. The boot
    // reconciliation set last_applied_policy_version to the on-disk schema
    // version (1), so the new envelope must be version >= 2.
    let policy_b = policy_for_paths(&[file_y.to_str().unwrap()], "standard");
    let env = SignedEnvelope {
        policy_version: 2,
        policy_bytes_b64: data_encoding::BASE64.encode(policy_b.as_bytes()),
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
    let result = agent.apply_policy(&resp).await;
    assert!(
        result.contains("\"ok\":true") || result.contains("\"outcome\":\"accepted\""),
        "apply_policy should be accepted, got: {result}"
    );

    // Give the reload task a beat to reconcile the live watcher.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Now writing Y produces a file_change — the live watcher reloaded. The
    // reload re-registered the FSEvents watch on a freshly-added directory, and
    // there's a brief window after re-registration before events start flowing,
    // so re-write Y until one lands. (The earlier X event is already in the
    // JSONL, so match on the path to avoid accepting that stale one.)
    let is_y_change = |v: &serde_json::Value| {
        v["evidence"]["kind"] == "file_change"
            && v["subject"]["value"]
                .as_str()
                .map(|p| p.ends_with("y.json"))
                .unwrap_or(false)
    };
    let mut ev_y = None;
    for i in 0..60 {
        std::fs::write(&file_y, format!("y{i}").as_bytes()).unwrap();
        if let Some(ev) = agent
            .wait_for_event(&is_y_change, Duration::from_millis(250))
            .await
        {
            ev_y = Some(ev);
            break;
        }
    }
    let ev = ev_y.expect("policy B: file_change for Y after live reload");
    assert_eq!(ev["schema_version"], 1);

    agent.join.abort();
}
