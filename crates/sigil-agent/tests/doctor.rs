use std::process::Command;

#[test]
fn it_doctor_succeeds_on_valid_config() {
    let bin = env!("CARGO_BIN_EXE_sigil");
    let out = Command::new(bin).arg("doctor").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Sigil doctor"));
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "unexpected exit code {code}\n{stdout}"
    );
}

#[test]
fn it_show_paths_prints_targets() {
    let bin = env!("CARGO_BIN_EXE_sigil");
    let out = Command::new(bin).args(["show", "paths"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("# "));
}

// Phase 3b.5 Task 6: doctor AI Guard section coverage.
//
// These tests assert observable doctor output:
//   1. The AI Guard section header always appears (agent-down fallback).
//   2. The static rubric table lists all 11 known reason kinds.
//   3. An operator override in policy.yaml renders with the `*` marker.

#[test]
fn doctor_prints_ai_guard_section_when_agent_down() {
    // Agent isn't running in this test binary's process. doctor should
    // still print the AI Guard section header + fallback message.
    let bin = env!("CARGO_BIN_EXE_sigil");
    let out = Command::new(bin).arg("doctor").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("──────────────  AI Guard  ──────────────"),
        "doctor output missing AI Guard section header. Output:\n{stdout}"
    );
    assert!(
        stdout.contains("sigil agent not running")
            || stdout.contains("Effective Rubric (static)"),
        "doctor missing fallback indicator. Output:\n{stdout}"
    );
}

#[test]
fn doctor_static_rubric_table_includes_all_eleven_kinds() {
    let bin = env!("CARGO_BIN_EXE_sigil");
    let out = Command::new(bin).arg("doctor").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    for kind in &[
        "destructive_in_inline_command",
        "destructive_in_hook_script",
        "sandbox_disabled",
        "no_sandbox",
        "permissions_allow_broad",
        "external_script_unscanned",
        "broad_matcher_pre_tool_use",
        "broad_matcher_other",
        "permissions_deny_empty",
        "mcp_server_remote",
        "mcp_server_local_command",
    ] {
        assert!(
            stdout.contains(kind),
            "doctor static rubric missing kind '{kind}'. Output:\n{stdout}"
        );
    }
}

#[test]
fn doctor_with_override_in_policy_shows_marker() {
    // Write a tempdir policy.yaml with an override; pass via --policy.
    // Verified flag: `sigil doctor --policy <PATH>` overrides the policy file path.
    let tmp = tempfile::tempdir().unwrap();
    let policy_path = tmp.path().join("policy.yaml");
    std::fs::write(
        &policy_path,
        r#"version: 1
host_id_strategy: hostname
rubric_overrides:
  destructive_in_hook_script: 5.0
"#,
    )
    .unwrap();
    let bin = env!("CARGO_BIN_EXE_sigil");
    let out = Command::new(bin)
        .arg("doctor")
        .arg("--policy")
        .arg(&policy_path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Find the row "destructive_in_hook_script ... 5.0 *"
    let found = stdout.lines().any(|l| {
        l.contains("destructive_in_hook_script") && l.contains("5.0") && l.contains('*')
    });
    assert!(
        found,
        "doctor missing override marker for destructive_in_hook_script. Output:\n{stdout}"
    );
}
