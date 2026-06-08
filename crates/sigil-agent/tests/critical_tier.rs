mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn it_critical_tier_emits_recheck() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("config.json");
    std::fs::write(&target, b"v1").unwrap();
    let policy = policy_for_paths(&[target.to_str().unwrap()], "critical");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    // Drive the file continuously until the watcher observes a change. OS
    // watchers (FSEvents, inotify) deliver from "now" and never replay, so a
    // write landing in the watcher's startup gap is lost forever; under heavy
    // parallel load that gap can swallow both fixed writes, hard-failing
    // regardless of the wait budget (#108, same family as #25). The background
    // writer guarantees a write the live stream can catch, then is aborted.
    let writer_target = target.clone();
    let writer = tokio::spawn(async move {
        let mut n: u64 = 0;
        loop {
            n += 1;
            let _ = std::fs::write(&writer_target, format!("v{n}").as_bytes());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let event = agent
        .wait_for_event(
            |v| v["evidence"]["kind"] == "file_change" && v["evidence"]["recheck_hash"].is_string(),
            common::fs_event_timeout(),
        )
        .await;

    writer.abort();
    let event = event.expect("recheck_hash should be populated for critical tier");
    assert!(event["evidence"]["recheck_hash"].as_str().unwrap().len() == 64);
    agent.join.abort();
}
