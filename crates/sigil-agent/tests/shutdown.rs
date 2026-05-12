mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "agent-runtime test: macOS-only for now (see CONTRIBUTING)"
)]
async fn it_graceful_shutdown_drains_queue() {
    let dir = tempfile::tempdir().unwrap();
    // Canonicalize: agent event paths are canonical; `/var` -> `/private/var` on macOS.
    let target = std::fs::canonicalize(dir.path()).unwrap().join("x.json");
    let policy = policy_for_paths(&[target.to_str().unwrap()], "standard");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;
    for i in 0..5 {
        std::fs::write(&target, format!("v{i}").as_bytes()).unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    agent.join.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let events = agent.read_all_events();
    assert!(!events.is_empty(), "expected at least one drained event");
}
