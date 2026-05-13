//! e2e: `reload_policy` nudges the policy_reload_task, which re-reads policy.yaml
//! from disk and swaps the live target set. Unix-only + feature-gated.
#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::{policy_for_paths, TestAgentBuilder};
use serde_json::json;
use std::time::Duration;

fn first_glob_of_test_target(payload: &serde_json::Value) -> Option<String> {
    payload["targets"]["targets"]
        .as_array()?
        .iter()
        .find(|t| {
            t["id"]
                .as_str()
                .map(|s| s.starts_with("test-target-"))
                .unwrap_or(false)
        })
        .and_then(|t| t["globs"][0].as_str().map(|s| s.to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_policy_picks_up_on_disk_edits() {
    let dir = tempfile::tempdir().unwrap();
    let path_a = dir.path().join("a.json");
    let path_b = dir.path().join("b.json");

    let policy_a = policy_for_paths(&[path_a.to_str().unwrap()], "standard");
    let agent = TestAgentBuilder::new().policy(&policy_a).start().await;

    // macOS canonicalizes /var → /private/var when expanding paths, so compare
    // by file-name suffix rather than full equality.
    let before = agent.control(&json!({"cmd": "targets"})).await;
    assert!(
        first_glob_of_test_target(&before)
            .as_deref()
            .map(|g| g.ends_with("a.json"))
            .unwrap_or(false),
        "initial target glob did not match a.json: {before}"
    );

    // Hand-edit policy.yaml on disk to policy B (watch b.json instead). The
    // agent's policy_reload_task is asleep — only `reload_policy` wakes it.
    let policy_b = policy_for_paths(&[path_b.to_str().unwrap()], "standard");
    std::fs::write(&agent.policy_file, &policy_b).unwrap();

    let reload_resp = agent.control(&json!({"cmd": "reload_policy"})).await;
    assert_eq!(reload_resp["ok"], true);

    // The IPC reply returns as soon as the watch is nudged, not when the
    // reload completes, so poll `targets` until the new policy is visible.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut after_glob: Option<String> = None;
    while std::time::Instant::now() < deadline {
        let after = agent.control(&json!({"cmd": "targets"})).await;
        after_glob = first_glob_of_test_target(&after);
        if after_glob.as_deref().map(|g| g.ends_with("b.json")) == Some(true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        after_glob
            .as_deref()
            .map(|g| g.ends_with("b.json"))
            .unwrap_or(false),
        "reload_policy did not swap globs from a.json → b.json within deadline (got {after_glob:?})"
    );

    agent.join.abort();
}
