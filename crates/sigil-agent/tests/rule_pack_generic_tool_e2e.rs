//! e2e: a generic (`tool: other`) UserGlobal rule pack through the real agent.
//!
//! Phase 3b.7.5 (#53) — proves that an operator-authored UserGlobal rule pack
//! naming an unknown tool via `tool: other` + `tool_label` is expanded into a
//! runtime parser, assessed by the agent's boot scan, and emits an
//! `AiGuardRiskAssessed` event whose wire `tool` is the bare string `"other"`,
//! whose `tool_label` carries the human name, and whose `reasons` include the
//! built-in `sandbox_disabled` reason the rule emitted.
//!
//! Why this is robust in the sandbox: a UserGlobal pack expands to exactly one
//! parser bound to an ABSOLUTE `on_file` (env-expanded, repo-independent). The
//! agent's boot scan synchronously assesses every parser at startup, so this
//! event is produced WITHOUT relying on FS-watcher delivery (issues #25/#66),
//! which is unreliable on macOS under `cargo test --workspace`.

#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::{fs_event_timeout, TestAgentBuilder};

/// Build a policy with one UserGlobal generic-tool rule pack `gen-acme`:
/// `tool: other` + `tool_label: acme-ai`, watching the absolute `config_path`
/// and matching top-level `$.sandbox == "false"` → `sandbox_disabled`.
fn generic_tool_pack_policy(config_path: &str) -> String {
    format!(
        r#"version: 1
host_id_strategy: machine_id
targets: []
rule_packs:
  - id: gen-acme
    pack_version: 1
    tool: other
    tool_label: "acme-ai"
    scope:
      kind: user_global
    watched_paths:
      - '{config_path}'
    rules:
      - id: r1
        on_file: '{config_path}'
        format: json
        selector: '$.sandbox'
        matcher:
          kind: equals
          value: "false"
        emit:
          kind: sandbox_disabled
"#
    )
}

/// A `tool: other` UserGlobal pack emits `AiGuardRiskAssessed` with the bare
/// wire `tool == "other"`, the `tool_label`, and the rule's built-in reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn generic_tool_pack_emits_other_with_label() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let config_dir = root.join("acme");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.json");
    std::fs::write(&config_path, r#"{"sandbox": false}"#).unwrap();

    let config_str = config_path.display().to_string();
    let policy = generic_tool_pack_policy(&config_str);
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let ev = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "other"
                    && v["evidence"]["tool_label"] == "acme-ai"
                    && v["evidence"]["rule_pack_id"] == "gen-acme"
            },
            fs_event_timeout(),
        )
        .await
        .expect("expected gen-acme AiGuardRiskAssessed with tool=other + label");

    let reasons = ev["evidence"]["reasons"].as_array().expect("reasons");
    assert!(
        reasons.iter().any(|r| r["kind"] == "sandbox_disabled"),
        "expected sandbox_disabled in reasons: {reasons:?}"
    );

    agent.join.abort();
}
