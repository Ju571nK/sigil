//! CLI e2e (#100): `sigil-hook install --agent cursor --enforce --write` must
//! actually write both Cursor gate events with the enforce command (+failClosed
//! when closed), and must NOT write an install baseline for cursor (spec D6).
#![cfg(unix)]
use std::process::Command;

#[test]
fn cursor_enforce_install_writes_both_events_and_no_baseline() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let state = home.join("state");

    let out = Command::new(env!("CARGO_BIN_EXE_sigil-hook"))
        .args([
            "install",
            "--agent",
            "cursor",
            "--enforce",
            "--on-failure",
            "closed",
            "--write",
        ])
        .env("HOME", home)
        .env("XDG_STATE_HOME", &state)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let hooks = std::fs::read_to_string(home.join(".cursor/hooks.json"))
        .expect("hooks.json must be written");
    let v: serde_json::Value = serde_json::from_str(&hooks).unwrap();
    for ev in ["beforeShellExecution", "beforeMCPExecution"] {
        let e = &v["hooks"][ev][0];
        assert!(
            e["command"].as_str().unwrap().contains("--enforce"),
            "{ev} entry must use the enforce command, got: {e}"
        );
        assert_eq!(
            e["failClosed"],
            serde_json::json!(true),
            "{ev} closed → failClosed"
        );
    }

    // D6: no baseline written for cursor.
    assert!(
        !state.join("sigil/hook-registration.json").exists(),
        "cursor install must not write a verify baseline"
    );
}
