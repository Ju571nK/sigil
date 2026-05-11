mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "FSEvents tempdir timing issue (Phase 1 known limit) — run with --ignored"]
async fn it_emits_modified_event() {
    let watch_path_template = format!(
        "{}/andeda-it-{}.json",
        std::env::temp_dir().display(),
        uuid::Uuid::new_v4().simple()
    );
    let policy = policy_for_paths(&[&watch_path_template], "standard");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let p = std::path::PathBuf::from(&watch_path_template);
    let _ = std::fs::remove_file(&p);
    std::fs::write(&p, b"first").unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    std::fs::write(&p, b"second").unwrap();

    let event = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "file_change"
                    && (v["evidence"]["change_kind"] == "modified"
                        || v["evidence"]["change_kind"] == "created")
            },
            Duration::from_secs(5),
        )
        .await
        .expect("expected file_change event");

    assert_eq!(event["schema_version"], 1);
    let _ = std::fs::remove_file(&p);
    agent.join.abort();
}
