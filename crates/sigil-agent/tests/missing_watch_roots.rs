mod common;
use common::{policy_for_paths, TestAgentBuilder};

async fn observes_late_directory(recursive: bool) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("not-yet-created/cache/tools");
    let file = if recursive {
        root.join("nested/snapshot.json")
    } else {
        root.join("settings.json")
    };
    let target = if recursive {
        root.join("*")
    } else {
        file.clone()
    };
    let policy = policy_for_paths(&[target.to_str().unwrap()], "standard")
        .replace("recursive: false", &format!("recursive: {recursive}"));
    sigil_core::policy::parse(&policy).expect("valid integration-test policy");
    let agent = TestAgentBuilder::new().policy(&policy).start().await;
    assert!(!root.exists());
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    // A single write, before reconciliation: repeated writes would hide the gap.
    std::fs::write(&file, b"first snapshot").unwrap();
    let expected = dunce::canonicalize(&file).unwrap();
    let observed = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "file_change"
                    && v["subject"]["value"]
                        .as_str()
                        .is_some_and(|p| std::path::Path::new(p) == expected)
            },
            common::fs_event_timeout(),
        )
        .await;
    agent.join.abort();
    assert!(
        observed.is_some(),
        "one-shot file creation in a late directory was lost"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recursive_directory_created_after_startup_is_observed() {
    observes_late_directory(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_parent_of_literal_target_is_recovered() {
    observes_late_directory(false).await;
}
