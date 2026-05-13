//! e2e: `policy_status` returns the daemon's boot-reconciled version + envelope
//! state. Unix-only + feature-gated.
#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::{policy_for_paths, TestAgentBuilder};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_status_returns_boot_reconciled_version() {
    let dir = tempfile::tempdir().unwrap();
    let watched = dir.path().join("a.json");
    let policy = policy_for_paths(&[watched.to_str().unwrap()], "standard");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let resp = agent.control(&json!({"cmd": "policy_status"})).await;
    assert_eq!(resp["ok"], true);
    let ps = &resp["policy_status"];
    assert!(
        ps["last_applied_policy_version"].is_number(),
        "policy_status payload missing last_applied_policy_version: {resp}"
    );
    assert_eq!(ps["last_applied_policy_version"], 1);
    assert!(ps["active_envelope_valid_until"].is_null());
    assert_eq!(ps["policy_expired_active"], false);

    agent.join.abort();
}
