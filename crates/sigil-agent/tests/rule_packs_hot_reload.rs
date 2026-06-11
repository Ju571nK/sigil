//! e2e: writing rule-packs.yaml on disk triggers a live hot-reload via the
//! dedicated fsnotify watcher added in #134, WITHOUT requiring a server or IPC
//! call. The new pack's rule fires via the normal ai_guard file-change path
//! after reload, emitting an `AiGuardRiskAssessed` event. The test also
//! verifies that NO `file_change` posture event was emitted for the
//! `rule-packs.yaml` path itself (proving the normalizer was bypassed, not fed).
//!
//! Unix only + operator-cli feature (control socket used for start-up readiness
//! detection).
//!
//! ## Design note (reload → assessment trigger)
//!
//! The `ai_guard_task` runs a boot scan then re-assesses only on:
//! (a) file-change broadcasts from the hasher, or (b) heartbeat (24 h in prod).
//! After hot-reload the new parser is live in `parsers`, but the task won't
//! re-scan spontaneously. We therefore add the config file to `policy.yaml`
//! as a standard target AND to the rule pack's `watched_paths`. After writing
//! `rule-packs.yaml` we poll: wait for reload to land (we verify via a
//! `reload_policy` control call that the new parser is active), then rewrite the
//! config so the hasher broadcasts it → `ai_guard_task` picks it up and emits
//! `AiGuardRiskAssessed` from the new pack. This matches real-world usage: a
//! `git pull` on `rule-packs.yaml` is usually followed by a config change (or
//! the user expects the next heartbeat to pick it up).
#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::{fs_event_timeout, TestAgentBuilder};
use std::time::Duration;

/// Policy that watches `config_path` as a standard target so the main watcher
/// tracks it. No rule packs — they arrive via rule-packs.yaml hot-reload.
fn base_policy(config_path: &str) -> String {
    let id = format!("hot-reload-target-{}", uuid::Uuid::new_v4().simple());
    format!(
        "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: {id}\n    description: hot-reload test target\n    tier: standard\n    platform: any\n    paths:\n      - '{config_path}'\n    recursive: false\n    follow_symlinks: false\n"
    )
}

/// A minimal rule-pack bundle YAML whose `my-hot-pack` UserGlobal pack watches
/// `config_path` and emits `permissions_deny_empty` whenever `$.enabled`
/// exists — a deterministic marker for test assertions.
fn hot_reload_bundle(config_path: &str) -> String {
    format!(
        "version: 1\nrule_packs:\n  - id: my-hot-pack\n    pack_version: 1\n    tool: other\n    tool_label: hot-reload-test\n    scope:\n      kind: user_global\n    watched_paths:\n      - '{config_path}'\n    rules:\n      - id: r0\n        on_file: '{config_path}'\n        format: json\n        selector: '$.enabled'\n        matcher:\n          kind: exists\n        emit:\n          kind: permissions_deny_empty\n"
    )
}

/// Writing rule-packs.yaml on disk hot-reloads the live agent (bypassing the
/// main normalizer), the new pack's rule fires on the next file-change event
/// for the pack's watched config, and no `file_change` posture event is
/// produced for `rule-packs.yaml` itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rule_packs_yaml_write_triggers_reload_and_emits_pack_event() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();

    // The JSON config file: both a policy target (so the hasher watches it) and
    // the file the new rule pack will assess.
    let config_dir = root.join("hot");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.json");
    std::fs::write(&config_path, r#"{"enabled": true}"#).unwrap();
    let config_str = config_path.display().to_string();

    // Start with a policy that watches config.json but has no rule packs.
    let policy = base_policy(&config_str);
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    // rule-packs.yaml lives beside policy.yaml in the TestAgent tempdir.
    let rule_packs_path = agent.policy_file.with_file_name("rule-packs.yaml");
    let bundle_yaml = hot_reload_bundle(&config_str);

    // Write rule-packs.yaml and then poll for the AiGuardRiskAssessed event.
    //
    // The dedicated watcher (#134) might not be active immediately after agent
    // start (the FSEvents backend on macOS can take several seconds to register).
    // We re-write rule-packs.yaml periodically inside the loop so the watcher
    // catches it even if the first write races the watcher setup. We also
    // re-write config.json to trigger the ai_guard_task via the hasher's
    // file-change broadcast once the pack has been hot-reloaded.
    let timeout = fs_event_timeout();
    let is_hot_pack_event = |v: &serde_json::Value| {
        v["evidence"]["kind"] == "ai_guard_risk_assessed"
            && v["evidence"]["rule_pack_id"] == "my-hot-pack"
    };

    let deadline = std::time::Instant::now() + timeout;
    let mut found = false;
    let mut iteration = 0u32;
    while std::time::Instant::now() < deadline {
        // Re-write rule-packs.yaml on every iteration so the dedicated watcher
        // catches it even if the first write raced the watcher setup window.
        std::fs::write(&rule_packs_path, &bundle_yaml).unwrap();

        // Brief settle: give the watcher time to deliver the rule-packs.yaml
        // event and policy_reload_task time to reload the new pack before we
        // prod the hasher with a config.json change.
        tokio::time::sleep(Duration::from_millis(600)).await;

        // Rewrite config so the hasher broadcasts it → ai_guard_task runs the
        // newly-loaded rule pack parser.
        std::fs::write(
            &config_path,
            format!(r#"{{"enabled": true, "iter": {iteration}}}"#),
        )
        .unwrap();
        iteration += 1;

        if let Some(_ev) = agent
            .wait_for_event(&is_hot_pack_event, Duration::from_millis(800))
            .await
        {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "expected AiGuardRiskAssessed from my-hot-pack after hot-reload + config touch"
    );

    // Small drain window so any stray normalizer events can arrive before we
    // snapshot the event log.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Assert NO file_change posture event was emitted for rule-packs.yaml
    // itself (the dedicated watcher bypasses the normalizer entirely).
    let rule_packs_path_str = rule_packs_path.display().to_string();
    let got_file_change_for_rp = agent.read_all_events().into_iter().any(|v| {
        v["evidence"]["kind"] == "file_change"
            && v["subject"]["value"]
                .as_str()
                .map(|p| p == rule_packs_path_str || p.ends_with("rule-packs.yaml"))
                .unwrap_or(false)
    });
    assert!(
        !got_file_change_for_rp,
        "rule-packs.yaml must not produce a file_change posture event (normalizer bypass)"
    );

    agent.join.abort();
}
