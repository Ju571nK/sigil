mod common;
use common::{policy_for_paths, policy_path, TestAgentBuilder};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    target_os = "windows",
    ignore = "agent-runtime test: not yet hardened for Windows"
)]
async fn it_critical_tier_emits_recheck() {
    let dir = tempfile::tempdir().unwrap();
    let target = policy_path(dir.path()).join("config.json");
    std::fs::write(&target, b"v1").unwrap();
    let policy = policy_for_paths(&[target.to_str().unwrap()], "critical");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    // First write — captured immediately (window=0).
    std::fs::write(&target, b"v2").unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::write(&target, b"v3").unwrap();

    let event = agent
        .wait_for_event(
            |v| v["evidence"]["kind"] == "file_change" && v["evidence"]["recheck_hash"].is_string(),
            Duration::from_secs(5),
        )
        .await
        .expect("recheck_hash should be populated for critical tier");
    assert!(event["evidence"]["recheck_hash"].as_str().unwrap().len() == 64);
    agent.join.abort();
}
