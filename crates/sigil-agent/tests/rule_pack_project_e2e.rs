//! e2e: Project-scope rule packs through the real agent.
//!
//! Phase 3b.7 Task 7 — proves that an operator-authored Project-scope rule
//! pack (`scope: { kind: project }`) is expanded per-repo across a
//! `gemini_workspaces` root, emits `AiGuardRiskAssessed` events carrying the
//! pack's `rule_pack_id` for attribution, coexists with the built-in
//! `GeminiProjectParser` (which emits NO `rule_pack_id`) without identity-key
//! collision, and is reconciled on policy reload when a repo is added.
//!
//! Fixture note: the rule pack rule selects TOP-LEVEL `$.sandbox`, while the
//! built-in `GeminiProjectParser` reads NESTED `tools.sandbox`. Tests 1 and 3
//! therefore use `{"sandbox": false}` (rule-pack only). Test 2 uses
//! `{"sandbox": false, "tools": {"sandbox": false}}` so BOTH parsers fire on
//! the same repo, exercising the (tool, scope, rule_pack_id) identity key.
//!
//! Sandbox caveat: this repo's CI sandbox does not deliver FS-watcher events
//! (issues #25/#66), so these tests — like the rest of the e2e suite
//! (`ai_guard_e2e`, `basic_events`, `critical_tier`) — may time out locally on
//! macOS. They are verified green on Linux CI (ubuntu/rocky).

#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::{fs_event_timeout, TestAgentBuilder};
use serde_json::json;
use std::time::Duration;

/// Build a policy with a `gemini_workspaces` root and one Project-scope rule
/// pack `proj-sbx` matching top-level `$.sandbox == "false"` → `sandbox_disabled`.
fn project_pack_policy(workspace: &str) -> String {
    format!(
        r#"version: 1
host_id_strategy: machine_id
gemini_workspaces:
  - '{workspace}'
targets: []
rule_packs:
  - id: proj-sbx
    pack_version: 1
    tool: gemini
    scope:
      kind: project
    watched_paths:
      - '.gemini/settings.json'
    rules:
      - id: r1
        on_file: '.gemini/settings.json'
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

fn write_gemini_settings(repo: &std::path::Path, body: &str) {
    let dir = repo.join(".gemini");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("settings.json"), body).unwrap();
}

/// Test 1 — a Project pack expands per-repo and attributes each finding with
/// its `rule_pack_id`. repoA (sandbox:false) → a `sandbox_disabled` finding
/// scoped to repoA with `rule_pack_id == "proj-sbx"`; repoB (sandbox:true)
/// produces no such finding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_pack_emits_per_repo_with_attribution() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let repo_a = root.join("repoA");
    let repo_b = root.join("repoB");
    write_gemini_settings(&repo_a, r#"{"sandbox": false}"#);
    write_gemini_settings(&repo_b, r#"{"sandbox": true}"#);

    let policy = project_pack_policy(&root.display().to_string());
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let canonical_a = dunce::canonicalize(&repo_a).unwrap().display().to_string();
    let canonical_b = dunce::canonicalize(&repo_b).unwrap().display().to_string();

    // repoA: rule-pack finding attributed to proj-sbx with sandbox_disabled.
    let ev_a = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "gemini"
                    && v["evidence"]["scope"]["kind"] == "project"
                    && v["evidence"]["scope"]["path"] == canonical_a.as_str()
                    && v["evidence"]["rule_pack_id"] == "proj-sbx"
            },
            fs_event_timeout(),
        )
        .await
        .expect("expected proj-sbx AiGuardRiskAssessed for repoA");
    let reasons_a = ev_a["evidence"]["reasons"].as_array().expect("reasons");
    assert!(
        reasons_a.iter().any(|r| r["kind"] == "sandbox_disabled"),
        "expected sandbox_disabled in repoA reasons: {reasons_a:?}"
    );

    // repoB (sandbox:true) must NOT produce a proj-sbx sandbox_disabled finding.
    // Bounded re-scan of all events to date: if such an event ever appears it is
    // a bug. (repoB may still emit a CLEAN assessment with empty reasons; we only
    // forbid a sandbox_disabled reason attributed to proj-sbx.)
    let bad_b = agent.read_all_events().into_iter().find(|v| {
        v["evidence"]["kind"] == "ai_guard_risk_assessed"
            && v["evidence"]["tool"] == "gemini"
            && v["evidence"]["scope"]["path"] == canonical_b.as_str()
            && v["evidence"]["rule_pack_id"] == "proj-sbx"
            && v["evidence"]["reasons"]
                .as_array()
                .map(|rs| rs.iter().any(|r| r["kind"] == "sandbox_disabled"))
                .unwrap_or(false)
    });
    assert!(
        bad_b.is_none(),
        "repoB (sandbox:true) must not yield a proj-sbx sandbox_disabled finding: {bad_b:?}"
    );

    agent.join.abort();
}

/// Test 2 — the Project pack coexists with the built-in `GeminiProjectParser`.
/// Both watch `.gemini/settings.json` and both fire on repoA, yielding TWO
/// distinct events: one with `rule_pack_id == "proj-sbx"` and one with NO
/// `rule_pack_id` (built-in). This proves the (tool, scope, rule_pack_id)
/// identity key prevents the two assessments from colliding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn project_pack_coexists_with_builtin() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let repo_a = root.join("repoA");
    // Satisfy BOTH parsers: rule pack reads top-level $.sandbox; the built-in
    // GeminiProjectParser reads nested tools.sandbox.
    write_gemini_settings(
        &repo_a,
        r#"{"sandbox": false, "tools": {"sandbox": false}}"#,
    );

    let policy = project_pack_policy(&root.display().to_string());
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let canonical_a = dunce::canonicalize(&repo_a).unwrap().display().to_string();

    // Collect events until BOTH the rule-pack and built-in assessments for
    // repoA are seen, or the deadline elapses.
    let deadline = std::time::Instant::now() + fs_event_timeout();
    let mut saw_pack = false;
    let mut saw_builtin = false;
    while std::time::Instant::now() < deadline && !(saw_pack && saw_builtin) {
        for v in agent.read_all_events() {
            let is_repo_a_gemini = v["evidence"]["kind"] == "ai_guard_risk_assessed"
                && v["evidence"]["tool"] == "gemini"
                && v["evidence"]["scope"]["kind"] == "project"
                && v["evidence"]["scope"]["path"] == canonical_a.as_str();
            if !is_repo_a_gemini {
                continue;
            }
            // sandbox_disabled must be present for either parser on this fixture.
            let has_sbx = v["evidence"]["reasons"]
                .as_array()
                .map(|rs| rs.iter().any(|r| r["kind"] == "sandbox_disabled"))
                .unwrap_or(false);
            if !has_sbx {
                continue;
            }
            if v["evidence"]["rule_pack_id"] == "proj-sbx" {
                saw_pack = true;
            } else if v["evidence"]["rule_pack_id"].is_null() {
                // Built-in parser: rule_pack_id field absent/null.
                saw_builtin = true;
            }
        }
        if saw_pack && saw_builtin {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        saw_pack,
        "expected a repoA gemini event WITH rule_pack_id=proj-sbx (rule pack)"
    );
    assert!(
        saw_builtin,
        "expected a repoA gemini event WITHOUT rule_pack_id (built-in GeminiProjectParser)"
    );

    agent.join.abort();
}

/// Test 3 — reload reconciliation: boot with only repoA on disk, then add
/// repoB and trigger a policy reload (rewrite policy.yaml + `reload_policy`).
/// A proj-sbx finding for repoB must appear after the reload. (Prune-on-remove
/// is covered by the Task 6 unit test
/// `policy_reload_task::tests::reload_project_pack_prunes_removed_repo`, which
/// can deterministically assert state-map removal without depending on the
/// FS watcher; asserting absence here would be watcher-timing-flaky.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_adds_then_prunes_repo() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let repo_a = root.join("repoA");
    let repo_b = root.join("repoB");
    // Boot with only repoA present.
    write_gemini_settings(&repo_a, r#"{"sandbox": false}"#);

    let policy = project_pack_policy(&root.display().to_string());
    let agent = TestAgentBuilder::new().policy(&policy).start().await;

    let canonical_a = dunce::canonicalize(&repo_a).unwrap().display().to_string();

    // Initial finding for repoA.
    agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "gemini"
                    && v["evidence"]["scope"]["path"] == canonical_a.as_str()
                    && v["evidence"]["rule_pack_id"] == "proj-sbx"
            },
            fs_event_timeout(),
        )
        .await
        .expect("expected initial proj-sbx finding for repoA");

    // repoB must exist on disk BEFORE reload so workspace discovery finds it
    // (discover_per_repo requires the `.gemini/settings.json` marker to exist).
    write_gemini_settings(&repo_b, r#"{"sandbox": false}"#);
    std::fs::write(&agent.policy_file, &policy).unwrap();
    let reload_resp = agent.control(&json!({"cmd": "reload_policy"})).await;
    assert_eq!(
        reload_resp["ok"], true,
        "reload_policy failed: {reload_resp}"
    );

    let canonical_b = dunce::canonicalize(&repo_b).unwrap().display().to_string();
    let repo_b_match = |v: &serde_json::Value| {
        v["evidence"]["kind"] == "ai_guard_risk_assessed"
            && v["evidence"]["tool"] == "gemini"
            && v["evidence"]["scope"]["kind"] == "project"
            && v["evidence"]["scope"]["path"] == canonical_b.as_str()
            && v["evidence"]["rule_pack_id"] == "proj-sbx"
    };

    // The `reload_policy` IPC reply returns before reload finishes arming the
    // watch, and repoB's settings were written before that watch existed — so the
    // pre-reload write produced no inotify event for it. A reload-added parser is
    // otherwise assessed only on the next file change to its watched path or the
    // periodic heartbeat (the same behavior as built-in per-repo parsers). So
    // re-touch repoB's settings (distinct bytes each iteration → a real change)
    // until the now-watched proj-sbx parser assesses it.
    let deadline = std::time::Instant::now() + fs_event_timeout();
    let mut ev_b = None;
    let mut nonce = 0;
    while std::time::Instant::now() < deadline {
        nonce += 1;
        write_gemini_settings(
            &repo_b,
            &format!(r#"{{"sandbox": false, "nonce": {nonce}}}"#),
        );
        if let Some(ev) = agent
            .wait_for_event(&repo_b_match, Duration::from_millis(500))
            .await
        {
            ev_b = Some(ev);
            break;
        }
    }
    let ev_b = ev_b.expect("expected proj-sbx finding for repoB after reload added it");
    let reasons_b = ev_b["evidence"]["reasons"].as_array().expect("reasons");
    assert!(
        reasons_b.iter().any(|r| r["kind"] == "sandbox_disabled"),
        "expected sandbox_disabled in repoB reasons after add+reload: {reasons_b:?}"
    );

    agent.join.abort();
}
