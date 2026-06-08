mod common;
use common::{policy_for_paths, TestAgentBuilder};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn it_emits_modified_event() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir
        .path()
        .join(format!("sigil-it-{}.json", uuid::Uuid::new_v4().simple()));
    let policy = policy_for_paths(&[p.to_str().unwrap()], "standard");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    // Drive the file continuously instead of writing twice with a fixed sleep.
    // OS watchers (FSEvents, inotify) deliver from "now" and never replay, so a
    // write that lands in the watcher's startup gap is lost forever — under
    // heavy parallel load that gap can swallow both fixed writes, hard-failing
    // regardless of the wait budget (#108). A background writer keeps modifying
    // the file until the assertion observes a change, guaranteeing a write the
    // live stream can catch; it's aborted as soon as the event arrives.
    let writer_path = p.clone();
    let writer = tokio::spawn(async move {
        let mut n: u64 = 0;
        loop {
            n += 1;
            let _ = std::fs::write(&writer_path, format!("change-{n}").as_bytes());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let event = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "file_change"
                    && (v["evidence"]["change_kind"] == "modified"
                        || v["evidence"]["change_kind"] == "created")
            },
            common::fs_event_timeout(),
        )
        .await;

    writer.abort();
    let event = event.expect("expected file_change event");

    assert_eq!(event["schema_version"], 1);
    agent.join.abort();
}
