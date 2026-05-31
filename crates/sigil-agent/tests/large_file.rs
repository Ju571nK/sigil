mod common;
use common::{fs_event_timeout, policy_for_paths, TestAgentBuilder};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn it_large_file_emits_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("big.bin");
    let policy = policy_for_paths(&[target.to_str().unwrap()], "standard");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    // 11 MB file.
    let bytes = vec![0u8; 11 * 1024 * 1024];
    std::fs::write(&target, &bytes).unwrap();

    let event = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "file_change"
                    && v["evidence"]["evidence_quality"] == "incomplete"
                    && v["evidence"]["size_after"] == 11 * 1024 * 1024
            },
            fs_event_timeout(),
        )
        .await
        .expect("expected incomplete-quality file_change");
    assert!(event["evidence"]["after_hash"].is_null());
    agent.join.abort();
}
