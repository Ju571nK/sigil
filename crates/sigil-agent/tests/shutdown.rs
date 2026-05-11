mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "FSEvents tempdir timing issue (Phase 1 known limit) — run with --ignored"]
async fn it_graceful_shutdown_drains_queue() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("x.json");
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
