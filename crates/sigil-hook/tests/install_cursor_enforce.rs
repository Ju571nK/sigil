//! CLI e2e (#100, #120): `sigil-hook install --agent cursor --enforce --write` must
//! actually write both Cursor gate events with the enforce command (+failClosed
//! when closed), and must write a per-agent baseline (hook-registration-cursor.json).
#![cfg(unix)]
use std::process::Command;

#[test]
fn cursor_enforce_install_writes_both_events_and_writes_baseline() {
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

    // #120: cursor now writes a per-agent baseline (the #119 D6 gate is removed).
    let baseline = state.join("sigil/hook-registration-cursor.json");
    assert!(
        baseline.exists(),
        "cursor install must write its per-agent baseline"
    );
    let b: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline).unwrap()).unwrap();
    assert_eq!(b["agent"], "cursor");
    // installed with --on-failure closed
    assert_eq!(
        b["fail_closed"],
        serde_json::json!(true),
        "baseline must record fail_closed=true when installed with --on-failure closed"
    );
}
