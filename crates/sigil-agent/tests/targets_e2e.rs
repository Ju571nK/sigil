//! e2e: `targets` returns the live compiled target set (test target + the
//! built-in defaults the agent merges in). Unix-only + feature-gated.
#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::{policy_for_paths, TestAgentBuilder};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn targets_returns_the_live_compiled_target_set() {
    let dir = tempfile::tempdir().unwrap();
    let watched = dir.path().join("a.json");
    let policy = policy_for_paths(&[watched.to_str().unwrap()], "critical");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let resp = agent.control(&json!({"cmd": "targets"})).await;
    assert_eq!(resp["ok"], true);
    let targets = resp["targets"]["targets"]
        .as_array()
        .expect("targets payload missing `targets` array");
    // Defaults plus our one user-defined target — count varies by platform, so
    // assert the test target is present rather than pinning the total.
    let mine = targets
        .iter()
        .find(|t| {
            t["id"]
                .as_str()
                .map(|s| s.starts_with("test-target-"))
                .unwrap_or(false)
        })
        .expect("test target absent from targets payload");
    assert_eq!(mine["tier"], "critical");
    let globs = mine["globs"].as_array().expect("target missing globs");
    assert_eq!(globs.len(), 1);
    // macOS canonicalizes /var → /private/var when expanding the path, so
    // compare by suffix rather than full equality.
    assert!(
        globs[0]
            .as_str()
            .unwrap()
            .ends_with(watched.file_name().unwrap().to_str().unwrap()),
        "glob {} did not match watched file {}",
        globs[0],
        watched.display()
    );

    agent.join.abort();
}
