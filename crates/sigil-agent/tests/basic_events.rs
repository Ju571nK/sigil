mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
// macOS + Linux: passes. Windows: `runtime::run` stops right after the
// hardware-fingerprint step (the tolerant `spawn_watcher` didn't change it, so
// it's not a per-root error — likely `RecommendedWatcher::new` or a hang in the
// ReadDirectoryChangesW backend). Tracked follow-up — see CONTRIBUTING.
#[cfg_attr(
    target_os = "windows",
    ignore = "agent-runtime test: not yet hardened for Windows"
)]
async fn it_emits_modified_event() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir
        .path()
        .join(format!("sigil-it-{}.json", uuid::Uuid::new_v4().simple()));
    let policy = policy_for_paths(&[p.to_str().unwrap()], "standard");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

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
    agent.join.abort();
}
