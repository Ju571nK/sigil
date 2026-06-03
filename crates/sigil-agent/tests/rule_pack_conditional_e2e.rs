//! e2e: a Tier-2 conditional-block (`when` gate) UserGlobal rule pack through
//! the real agent.
//!
//! Phase 3b.7 (#53) — proves that an operator-authored UserGlobal rule pack with
//! `pack_version: 2` and a `when:` gate is expanded into a runtime parser,
//! assessed by the agent's boot scan, and emits its `sandbox_disabled` reason
//! ONLY when the gate holds:
//!   * Fixture A — `autoApprove == "true"` → gate holds → `sandbox_disabled` IS
//!     emitted in the `AiGuardRiskAssessed` reasons.
//!   * Fixture B — `autoApprove == "false"` → gate fails → `sandbox_disabled` is
//!     SUPPRESSED (absent from reasons), while an ungated control rule still
//!     fires so we know the boot scan actually ran.
//!
//! Why this is robust in the sandbox: a UserGlobal pack expands to exactly one
//! parser bound to an ABSOLUTE `on_file` (repo-independent). The agent's boot
//! scan synchronously assesses every parser at startup, so these events are
//! produced WITHOUT relying on FS-watcher delivery (issues #25/#66), which is
//! unreliable on macOS under `cargo test --workspace`.
//!
//! pack_version MUST be 2: `pack_is_loadable` rejects a v1 pack carrying any
//! non-empty `when` block (over-emit guard), so a v1 pack here would silently
//! refuse to load and never emit — a false failure.

#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::{fs_event_timeout, TestAgentBuilder};

/// Build a policy with one UserGlobal Tier-2 (`pack_version: 2`) rule pack
/// `cond-pack` (`tool: other` + `tool_label: acme-ai`, mirroring the
/// generic-tool e2e), watching the absolute `config_path`.
///
/// `r1` matches top-level `$.sandbox == "false"` → `sandbox_disabled`, but only
/// `when` `$.autoApprove == "true"`. `r0` is an ungated control rule that always
/// emits `permissions_deny_empty` whenever `$.sandbox` exists — a deterministic
/// "boot scan ran" marker that does NOT depend on the gate, so the suppression
/// case can assert absence against a known-complete scan (no racy wait).
fn conditional_pack_policy(config_path: &str) -> String {
    format!(
        r#"version: 1
host_id_strategy: machine_id
targets: []
rule_packs:
  - id: cond-pack
    pack_version: 2
    tool: other
    tool_label: "acme-ai"
    scope:
      kind: user_global
    watched_paths:
      - '{config_path}'
    rules:
      - id: r0
        on_file: '{config_path}'
        format: json
        selector: '$.sandbox'
        matcher:
          kind: exists
        emit:
          kind: permissions_deny_empty
      - id: r1
        on_file: '{config_path}'
        format: json
        selector: '$.sandbox'
        matcher:
          kind: equals
          value: "false"
        emit:
          kind: sandbox_disabled
        when:
          - selector: '$.autoApprove'
            matcher:
              kind: equals
              value: "true"
"#
    )
}

/// Write `<tmp>/acme/config.json` with the given body and return `(tempdir,
/// absolute config path string)`. The tempdir guard must outlive the agent.
fn fixture(body: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let config_dir = root.join("acme");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.json");
    std::fs::write(&config_path, body).unwrap();
    let config_str = config_path.display().to_string();
    (dir, config_str)
}

/// Fixture A: `autoApprove == true` → the `when` gate holds → `sandbox_disabled`
/// IS emitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conditional_pack_emits_when_gate_holds() {
    let (_dir, config_str) = fixture(r#"{"sandbox": false, "autoApprove": true}"#);
    let policy = conditional_pack_policy(&config_str);
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let ev = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "other"
                    && v["evidence"]["tool_label"] == "acme-ai"
                    && v["evidence"]["rule_pack_id"] == "cond-pack"
            },
            fs_event_timeout(),
        )
        .await
        .expect("expected cond-pack AiGuardRiskAssessed (gate holds)");

    let reasons = ev["evidence"]["reasons"].as_array().expect("reasons");
    assert!(
        reasons.iter().any(|r| r["kind"] == "sandbox_disabled"),
        "gate holds → expected sandbox_disabled in reasons: {reasons:?}"
    );

    agent.join.abort();
}

/// Fixture B: `autoApprove == false` → the `when` gate fails → `sandbox_disabled`
/// is SUPPRESSED. The ungated control rule still emits `permissions_deny_empty`,
/// giving us a deterministic boot-scan-complete marker; once that event has
/// arrived we snapshot all events and assert NO `sandbox_disabled` is present
/// (non-racy absence assertion — not a wait-for-absence).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conditional_pack_suppressed_when_gate_fails() {
    let (_dir, config_str) = fixture(r#"{"sandbox": false, "autoApprove": false}"#);
    let policy = conditional_pack_policy(&config_str);
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    // Wait for the ungated control reason — proves the boot scan assessed this
    // pack to completion, so any (suppressed) sandbox_disabled would already be
    // on disk by now.
    let ev = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["rule_pack_id"] == "cond-pack"
                    && v["evidence"]["reasons"]
                        .as_array()
                        .map(|rs| rs.iter().any(|r| r["kind"] == "permissions_deny_empty"))
                        .unwrap_or(false)
            },
            fs_event_timeout(),
        )
        .await
        .expect("expected cond-pack control event (permissions_deny_empty)");

    // Sanity: the control marker is present...
    let reasons = ev["evidence"]["reasons"].as_array().expect("reasons");
    assert!(
        reasons
            .iter()
            .any(|r| r["kind"] == "permissions_deny_empty"),
        "expected control reason permissions_deny_empty: {reasons:?}"
    );

    // ...and across the full event snapshot, the gated reason never emitted.
    let suppressed = agent.read_all_events().into_iter().all(|v| {
        if v["evidence"]["kind"] != "ai_guard_risk_assessed"
            || v["evidence"]["rule_pack_id"] != "cond-pack"
        {
            return true;
        }
        v["evidence"]["reasons"]
            .as_array()
            .map(|rs| rs.iter().all(|r| r["kind"] != "sandbox_disabled"))
            .unwrap_or(true)
    });
    assert!(
        suppressed,
        "gate fails (autoApprove=false) → sandbox_disabled must be suppressed"
    );

    agent.join.abort();
}
