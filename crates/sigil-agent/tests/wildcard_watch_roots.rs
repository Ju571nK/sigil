mod common;
use common::{fs_event_timeout, policy_for_paths, TestAgent, TestAgentBuilder};
use std::path::Path;

fn isolated_policy(pattern: &Path) -> String {
    let mut yaml = policy_for_paths(&[pattern.to_str().unwrap()], "standard");
    yaml.push_str("overrides:\n");
    for target in sigil_core::policy::defaults().unwrap().targets {
        yaml.push_str(&format!("  - id: {}\n    disabled: true\n", target.id));
    }
    yaml
}

async fn expect_file(agent: &TestAgent, file: &Path) {
    let canonical = dunce::canonicalize(file).unwrap();
    assert!(
        agent
            .wait_for_event(
                |event| {
                    event["evidence"]["kind"] == "file_change"
                        && event["subject"]["value"]
                            .as_str()
                            .is_some_and(|p| Path::new(p) == canonical)
                },
                fs_event_timeout()
            )
            .await
            .is_some(),
        "missing event for {}",
        file.display()
    );
}

async fn lifecycle(poll: bool) {
    let td = tempfile::tempdir().unwrap();
    let apps = td.path().join("Applications");
    let existing = apps.join("Existing.app/Contents/Info.plist");
    std::fs::create_dir_all(existing.parent().unwrap()).unwrap();
    let policy = isolated_policy(&apps.join("*.app/Contents/Info.plist"));
    let agent = TestAgentBuilder::new()
        .policy(&policy)
        .poll_watcher(poll)
        .start()
        .await;
    std::fs::write(&existing, b"existing app changed").unwrap();
    expect_file(&agent, &existing).await;
    let late = apps.join("Late.app/Contents/Info.plist");
    std::fs::create_dir_all(late.parent().unwrap()).unwrap();
    std::fs::write(&late, b"single write before discovery").unwrap();
    expect_file(&agent, &late).await;
    // Catch-up scans may see unrelated leaves, but normalizer filtering must not emit them.
    let unrelated = apps.join("Other.app/Contents/unrelated.txt");
    std::fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    std::fs::write(&unrelated, b"outside target").unwrap();
    let matching = unrelated.with_file_name("Info.plist");
    std::fs::write(&matching, b"inside target").unwrap();
    expect_file(&agent, &matching).await;
    assert!(!agent.read_all_events().iter().any(|event| {
        event["subject"]["value"]
            .as_str()
            .is_some_and(|p| p.ends_with("unrelated.txt"))
    }));
    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_wildcard_roots_reach_the_event_sink() {
    lifecycle(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_wildcard_roots_reach_the_event_sink() {
    lifecycle(true).await;
}

#[cfg(all(unix, feature = "operator-cli"))]
async fn reload(poll: bool) {
    let td = tempfile::tempdir().unwrap();
    let initial = td.path().join("initial/settings.json");
    let agent = TestAgentBuilder::new()
        .policy(&isolated_policy(&initial))
        .poll_watcher(poll)
        .start()
        .await;
    let pattern = td.path().join("Applications/*.app/Contents/Info.plist");
    let file = td.path().join("Applications/New.app/Contents/Info.plist");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, b"present before reload").unwrap();
    std::fs::write(&agent.policy_file, isolated_policy(&pattern)).unwrap();
    assert_eq!(
        agent
            .control(&serde_json::json!({"cmd":"reload_policy"}))
            .await["ok"],
        true
    );
    expect_file(&agent, &file).await;
    std::fs::write(&agent.policy_file, isolated_policy(&initial)).unwrap();
    assert_eq!(
        agent
            .control(&serde_json::json!({"cmd":"reload_policy"}))
            .await["ok"],
        true
    );
    let deadline = tokio::time::Instant::now() + fs_event_timeout();
    loop {
        let response = agent.control(&serde_json::json!({"cmd":"targets"})).await;
        if response["targets"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| {
                t["globs"].as_array().unwrap().iter().any(|g| {
                    g.as_str()
                        .is_some_and(|g| g.ends_with("initial/settings.json"))
                })
            })
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let removed = td
        .path()
        .join("Applications/Removed.app/Contents/Info.plist");
    std::fs::create_dir_all(removed.parent().unwrap()).unwrap();
    std::fs::write(&removed, b"removed policy").unwrap();
    let canonical = dunce::canonicalize(&removed).unwrap();
    assert!(agent
        .wait_for_event(
            |event| {
                event["subject"]["value"]
                    .as_str()
                    .is_some_and(|p| Path::new(p) == canonical)
            },
            std::time::Duration::from_secs(6)
        )
        .await
        .is_none());
    agent.join.abort();
}

#[cfg(all(unix, feature = "operator-cli"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_reload_adds_and_removes_wildcard_roots() {
    reload(false).await;
}

#[cfg(all(unix, feature = "operator-cli"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_reload_adds_and_removes_wildcard_roots() {
    reload(true).await;
}
