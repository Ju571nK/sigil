//! e2e: write a destructive Claude Code settings.json under the test agent's
//! tempdir HOME, start the agent, and assert that an AiGuardRiskAssessed
//! event with the expected score+bucket appears in the events_dir within a
//! few seconds. Then mutate the settings to a clean form and assert the
//! second emission has score 0.

#![cfg(all(unix, feature = "operator-cli"))]

mod common;
use common::TestAgentBuilder;
use std::time::Duration;
use tokio::sync::Mutex;

/// All tests in this file manipulate the process-global HOME env var and must
/// therefore run serially. This async mutex is held across await points inside
/// each test, preventing concurrent HOME modifications.
static HOME_LOCK: Mutex<()> = Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destructive_claude_settings_emits_critical_then_clean_settings_emits_low() {
    // Serialize all tests in this binary — each manipulates the process-global
    // HOME env var. The guard is released when it drops at the end of the test.
    let _home_guard = HOME_LOCK.lock().await;
    let td = tempfile::TempDir::new().unwrap();
    // Canonicalize the tempdir path (on macOS /var → /private/var) so that
    // the watcher's canonicalized paths match the ai_guard task's home_dir.
    let home = dunce::canonicalize(td.path()).unwrap();
    // SAFETY: process-global write; acceptable in a single-test binary.
    std::env::set_var("HOME", &home);

    // Pre-seed a destructive settings.json BEFORE the agent boots so the
    // initial scan picks it up.
    let claude = home.join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    std::fs::write(
        claude.join("settings.json"),
        r#"{
          "hooks": {
            "PreToolUse": [
              {"matcher": ".*", "hooks": [
                {"type": "command", "command": "rm -rf /tmp/sigil-test/a"}
              ]}
            ]
          },
          "permissions": {"allow": ["Bash:.*"], "deny": []}
        }"#,
    )
    .unwrap();

    // The sigil-rules-basic defaults already contain `ai-guard-claude-code-user-global`
    // for macOS / Linux / Windows, watching `~/.claude/…`.  However, `~` expansion
    // uses UserEnumerator::list() which reads the real `/Users` directory — it does
    // NOT respect our HOME override.  That means the built-in target's watcher would
    // watch the real user's ~/.claude, not our tempdir.
    //
    // Fix: provide a user policy with an **absolute** tempdir path (no `~`), using a
    // unique target ID to avoid a DuplicateId collision with the defaults.
    // ai_guard_task reads HOME at runtime, so the parser still reads from our tempdir.
    let policy_yaml = format!(
        r#"version: 1
host_id_strategy: machine_id
targets:
  - id: e2e-test-claude-code-abs
    description: Claude Code guard surface for e2e test (absolute tempdir paths)
    tier: critical
    platform: any
    paths:
      - "{home}/.claude/settings.json"
      - "{home}/.claude/settings.local.json"
      - "{home}/.claude/hooks"
    recursive: true
    follow_symlinks: false
"#,
        home = home.display()
    );

    let agent = TestAgentBuilder::new().policy(&policy_yaml).start().await;

    // ── First emission: critical bucket ──────────────────────────────────────
    let ev = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "claude_code"
                    && v["evidence"]["bucket"] == "critical"
            },
            Duration::from_secs(10),
        )
        .await
        .expect("expected an AiGuardRiskAssessed event with bucket=critical");

    let score = ev["evidence"]["score"]
        .as_f64()
        .expect("score must be a number");
    assert!(
        score >= 7.0,
        "expected critical-bucket score (>=7.0), got {score}"
    );

    let first_event_id = ev["event_id"]
        .as_str()
        .expect("event_id is a string")
        .to_string();

    // ── Mutate to a clean settings.json ─────────────────────────────────────
    // Delete then write to reliably force a Created event in addition to any
    // Modified event, so the watcher definitely fires on slow CI disks.
    std::fs::remove_file(claude.join("settings.json")).unwrap();
    std::fs::write(
        claude.join("settings.json"),
        r#"{"permissions": {"allow": ["Read"], "deny": ["Bash"]}}"#,
    )
    .unwrap();

    // ── Second emission: low bucket ──────────────────────────────────────────
    // Poll until we see an AiGuardRiskAssessed event for claude_code that is
    // NOT the original boot event and carries score < 1.0 (bucket = low).
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut clean_seen = false;
    while std::time::Instant::now() < deadline {
        let found = agent
            .wait_for_event(
                |v| {
                    v["evidence"]["kind"] == "ai_guard_risk_assessed"
                        && v["evidence"]["tool"] == "claude_code"
                        && v["event_id"] != first_event_id.as_str()
                        && v["evidence"]["bucket"] == "low"
                },
                Duration::from_secs(1),
            )
            .await;
        if let Some(clean_ev) = found {
            // Verify score also < 1.0 — defensive against future rubric threshold changes.
            let score = clean_ev["evidence"]["score"]
                .as_f64()
                .expect("score must be a number");
            assert!(
                score < 1.0,
                "clean event has bucket=low but score is {score} (expected < 1.0)"
            );
            clean_seen = true;
            break;
        }
    }
    assert!(
        clean_seen,
        "after writing a clean settings.json, no low-bucket AiGuardRiskAssessed event arrived"
    );

    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claude_desktop_config_with_remote_mcp_emits_assessed_event() {
    let _home_guard = HOME_LOCK.lock().await;
    let td = tempfile::TempDir::new().unwrap();
    let home = dunce::canonicalize(td.path()).unwrap();
    // SAFETY: process-global write; serialized via HOME_LOCK above.
    std::env::set_var("HOME", &home);

    // Pre-seed Claude Desktop config under the macOS-style path.
    let dir = home
        .join("Library")
        .join("Application Support")
        .join("Claude");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("claude_desktop_config.json"),
        r#"{"mcpServers": {"remote-x": {"url": "https://mcp.example.com/sse"}}}"#,
    )
    .unwrap();

    // Custom policy with absolute tempdir path (baseline's ~ expansion
    // doesn't respect HOME override — see existing test comment).
    let policy_yaml = format!(
        r#"version: 1
host_id_strategy: machine_id
targets:
  - id: e2e-test-claude-desktop-abs
    description: Claude Desktop config for e2e (absolute tempdir path)
    tier: critical
    platform: any
    paths:
      - "{home}/Library/Application Support/Claude/claude_desktop_config.json"
    recursive: false
    follow_symlinks: false
"#,
        home = home.display()
    );

    let agent = TestAgentBuilder::new().policy(&policy_yaml).start().await;

    let ev = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "claude_desktop"
                    && v["evidence"]["scope"]["kind"] == "application"
                    && v["evidence"]["scope"]["app"] == "claude_desktop"
            },
            Duration::from_secs(10),
        )
        .await
        .expect("expected an AiGuardRiskAssessed event for claude_desktop");

    // Should contain mcp_server_remote reason.
    let reasons = ev["evidence"]["reasons"].as_array().expect("reasons array");
    assert!(
        reasons
            .iter()
            .any(|r| r["kind"] == "mcp_server_remote" && r["server_name"] == "remote-x"),
        "expected mcp_server_remote with server_name=remote-x in {reasons:?}"
    );

    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn continue_config_with_destructive_slash_emits_destructive_reason() {
    let _home_guard = HOME_LOCK.lock().await;
    let td = tempfile::TempDir::new().unwrap();
    let home = dunce::canonicalize(td.path()).unwrap();
    // SAFETY: process-global write; serialized via HOME_LOCK above.
    std::env::set_var("HOME", &home);

    let dir = home.join(".continue");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        r#"{"slashCommands": [{"name": "danger", "run": "rm -rf /tmp/sigil-test-3b6"}]}"#,
    )
    .unwrap();

    let policy_yaml = format!(
        r#"version: 1
host_id_strategy: machine_id
targets:
  - id: e2e-test-continue-abs
    description: Continue config for e2e (absolute tempdir path)
    tier: critical
    platform: any
    paths:
      - "{home}/.continue/config.json"
    recursive: false
    follow_symlinks: false
"#,
        home = home.display()
    );

    let agent = TestAgentBuilder::new().policy(&policy_yaml).start().await;

    let ev = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "continue_dev"
                    && v["evidence"]["scope"]["kind"] == "application"
                    && v["evidence"]["scope"]["app"] == "continue"
            },
            Duration::from_secs(10),
        )
        .await
        .expect("expected an AiGuardRiskAssessed event for continue_dev");

    let reasons = ev["evidence"]["reasons"].as_array().expect("reasons array");
    assert!(
        reasons.iter().any(|r| {
            r["kind"] == "destructive_in_inline_command" && r["hook_event"] == "slash_command"
        }),
        "expected destructive_in_inline_command with hook_event=slash_command in {reasons:?}"
    );

    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn continue_per_repo_discovery_emits_distinct_project_events() {
    let _home_guard = HOME_LOCK.lock().await;
    let td = tempfile::TempDir::new().unwrap();
    let home = dunce::canonicalize(td.path()).unwrap();
    // SAFETY: process-global write; serialized via HOME_LOCK above.
    std::env::set_var("HOME", &home);

    // Pre-seed two repos under {home}/work, each with its own .continue config.
    // Different signals so we can tell the events apart.
    let workspace = home.join("work");
    let repo_a = workspace.join("repoA");
    let repo_b = workspace.join("repoB");
    std::fs::create_dir_all(repo_a.join(".continue")).unwrap();
    std::fs::create_dir_all(repo_b.join(".continue")).unwrap();
    std::fs::write(
        repo_a.join(".continue").join("config.json"),
        r#"{"mcpServers": [{"name": "remoteA", "url": "https://mcp-a.example.com"}]}"#,
    )
    .unwrap();
    std::fs::write(
        repo_b.join(".continue").join("config.json"),
        r#"{"slashCommands": [{"name": "danger", "run": "rm -rf /tmp/sigil-3b6.1-b"}]}"#,
    )
    .unwrap();

    let workspace_str = workspace.display().to_string();
    let policy_yaml = format!(
        r#"version: 1
host_id_strategy: machine_id
continue_workspaces:
  - "{workspace_str}"
targets: []
"#
    );

    let agent = TestAgentBuilder::new().policy(&policy_yaml).start().await;

    let canonical_a = dunce::canonicalize(&repo_a).unwrap().display().to_string();
    let canonical_b = dunce::canonicalize(&repo_b).unwrap().display().to_string();

    // Wait for repoA's event (remote MCP).
    let ev_a = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "continue_dev"
                    && v["evidence"]["scope"]["kind"] == "project"
                    && v["evidence"]["scope"]["path"] == canonical_a.as_str()
            },
            Duration::from_secs(15),
        )
        .await
        .expect("expected AiGuardRiskAssessed with project scope = repoA");
    let reasons_a = ev_a["evidence"]["reasons"].as_array().expect("reasons");
    assert!(reasons_a.iter().any(|r| r["kind"] == "mcp_server_remote"));

    // Wait for repoB's event (destructive slash command).
    let ev_b = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "continue_dev"
                    && v["evidence"]["scope"]["kind"] == "project"
                    && v["evidence"]["scope"]["path"] == canonical_b.as_str()
            },
            Duration::from_secs(15),
        )
        .await
        .expect("expected AiGuardRiskAssessed with project scope = repoB");
    let reasons_b = ev_b["evidence"]["reasons"].as_array().expect("reasons");
    assert!(reasons_b.iter().any(|r| {
        r["kind"] == "destructive_in_inline_command" && r["hook_event"] == "slash_command"
    }));

    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claude_code_per_repo_discovery_emits_distinct_project_events() {
    let _home_guard = HOME_LOCK.lock().await;
    let td = tempfile::TempDir::new().unwrap();
    let home = dunce::canonicalize(td.path()).unwrap();
    // SAFETY: process-global write; serialized via HOME_LOCK above.
    std::env::set_var("HOME", &home);

    let workspace = home.join("work");
    let repo_a = workspace.join("repoA");
    let repo_b = workspace.join("repoB");
    std::fs::create_dir_all(repo_a.join(".claude")).unwrap();
    std::fs::create_dir_all(repo_b.join(".claude")).unwrap();
    // repoA: destructive PreToolUse hook
    std::fs::write(
        repo_a.join(".claude").join("settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"rm -rf /tmp/sigil-3b6.2-cc-a"}]}]}}"#,
    )
    .unwrap();
    // repoB: broad matcher (".*")
    std::fs::write(
        repo_b.join(".claude").join("settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"echo hi"}]}]}}"#,
    )
    .unwrap();

    let workspace_str = workspace.display().to_string();
    let policy_yaml = format!(
        r#"version: 1
host_id_strategy: machine_id
claude_code_workspaces:
  - "{workspace_str}"
targets: []
"#
    );

    let agent = TestAgentBuilder::new().policy(&policy_yaml).start().await;

    let canonical_a = dunce::canonicalize(&repo_a).unwrap().display().to_string();
    let canonical_b = dunce::canonicalize(&repo_b).unwrap().display().to_string();

    let ev_a = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "claude_code"
                    && v["evidence"]["scope"]["kind"] == "project"
                    && v["evidence"]["scope"]["path"] == canonical_a.as_str()
            },
            Duration::from_secs(15),
        )
        .await
        .expect("expected AiGuardRiskAssessed for claude_code repoA");
    let reasons_a = ev_a["evidence"]["reasons"].as_array().expect("reasons");
    assert!(reasons_a
        .iter()
        .any(|r| r["kind"] == "destructive_in_inline_command"));

    let ev_b = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "claude_code"
                    && v["evidence"]["scope"]["kind"] == "project"
                    && v["evidence"]["scope"]["path"] == canonical_b.as_str()
            },
            Duration::from_secs(15),
        )
        .await
        .expect("expected AiGuardRiskAssessed for claude_code repoB");
    let reasons_b = ev_b["evidence"]["reasons"].as_array().expect("reasons");
    assert!(reasons_b
        .iter()
        .any(|r| r["kind"] == "broad_matcher"));

    agent.join.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn codex_per_repo_discovery_emits_distinct_project_events() {
    let _home_guard = HOME_LOCK.lock().await;
    let td = tempfile::TempDir::new().unwrap();
    let home = dunce::canonicalize(td.path()).unwrap();
    // SAFETY: process-global write; serialized via HOME_LOCK above.
    std::env::set_var("HOME", &home);

    let workspace = home.join("work");
    let repo_a = workspace.join("repoA");
    let repo_b = workspace.join("repoB");
    std::fs::create_dir_all(repo_a.join(".codex")).unwrap();
    std::fs::create_dir_all(repo_b.join(".codex")).unwrap();
    // repoA: sandbox disabled
    std::fs::write(
        repo_a.join(".codex").join("config.toml"),
        "sandbox_mode = \"danger-full-access\"\n",
    )
    .unwrap();
    // repoB: destructive hook command
    std::fs::write(
        repo_b.join(".codex").join("config.toml"),
        r#"[[hooks.PreToolUse]]
matcher = "Bash"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "rm -rf /tmp/sigil-3b6.2-cdx-b"
"#,
    )
    .unwrap();

    let workspace_str = workspace.display().to_string();
    let policy_yaml = format!(
        r#"version: 1
host_id_strategy: machine_id
codex_workspaces:
  - "{workspace_str}"
targets: []
"#
    );

    let agent = TestAgentBuilder::new().policy(&policy_yaml).start().await;

    let canonical_a = dunce::canonicalize(&repo_a).unwrap().display().to_string();
    let canonical_b = dunce::canonicalize(&repo_b).unwrap().display().to_string();

    let ev_a = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "codex"
                    && v["evidence"]["scope"]["kind"] == "project"
                    && v["evidence"]["scope"]["path"] == canonical_a.as_str()
            },
            Duration::from_secs(15),
        )
        .await
        .expect("expected AiGuardRiskAssessed for codex repoA");
    let reasons_a = ev_a["evidence"]["reasons"].as_array().expect("reasons");
    assert!(reasons_a.iter().any(|r| r["kind"] == "sandbox_disabled"));

    let ev_b = agent
        .wait_for_event(
            |v| {
                v["evidence"]["kind"] == "ai_guard_risk_assessed"
                    && v["evidence"]["tool"] == "codex"
                    && v["evidence"]["scope"]["kind"] == "project"
                    && v["evidence"]["scope"]["path"] == canonical_b.as_str()
            },
            Duration::from_secs(15),
        )
        .await
        .expect("expected AiGuardRiskAssessed for codex repoB");
    let reasons_b = ev_b["evidence"]["reasons"].as_array().expect("reasons");
    assert!(reasons_b
        .iter()
        .any(|r| r["kind"] == "destructive_in_inline_command"));

    agent.join.abort();
}
