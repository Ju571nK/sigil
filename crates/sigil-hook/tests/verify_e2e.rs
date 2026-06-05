//! E2E (#100): `sigil-hook verify` against temp baseline + settings, plus a
//! stub hook.sock to confirm the drift emit.
#![cfg(unix)]
use std::io::Read;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};

fn blake3_hex(s: &str) -> String {
    blake3::hash(s.as_bytes()).to_hex().to_string()
}

/// Write the baseline (under XDG_STATE_HOME=state) + a settings file.
fn setup(state: &std::path::Path, settings: &std::path::Path, matcher: &str, settings_json: &str) {
    let exe = "/usr/bin/sigil-hook";
    let cmd = format!("{exe} claude-code --capture redacted");
    let baseline = serde_json::json!({
        "agent": "claude-code",
        "settings_path": settings.to_string_lossy(),
        "command": cmd,
        "capture": "redacted",
        "matcher": matcher,
        "block_hash": blake3_hex(&cmd),
        "written_at_unix": 0
    });
    let dir = state.join("sigil");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("hook-registration.json"),
        serde_json::to_vec(&baseline).unwrap(),
    )
    .unwrap();
    std::fs::write(settings, settings_json).unwrap();
}

fn run_verify(state: &std::path::Path, stub_socket: Option<&std::path::Path>) -> i32 {
    let exe = env!("CARGO_BIN_EXE_sigil-hook");
    let mut c = Command::new(exe);
    c.arg("verify")
        .env("XDG_STATE_HOME", state)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(s) = stub_socket {
        c.env("SIGIL_HOOK_SOCKET", s);
    }
    c.status().unwrap().code().unwrap_or(-1)
}

const CLEAN: &str = r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/bin/sigil-hook claude-code --capture redacted"}]}]}}"#;
const NARROWED: &str = r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/bin/sigil-hook claude-code --capture redacted"}]}]}}"#;
const FOREIGN: &str = r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/other/tool run"}]}]}}"#;
const COMMAND_DRIFT: &str = r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/bin/sigil-hook claude-code --capture raw"}]}]}}"#;

#[test]
fn clean_exits_0() {
    let state = tempfile::tempdir().unwrap();
    let sdir = tempfile::tempdir().unwrap();
    let settings = sdir.path().join("settings.json");
    setup(state.path(), &settings, "*", CLEAN);
    assert_eq!(run_verify(state.path(), None), 0);
}

#[test]
fn matcher_drift_exits_2() {
    let state = tempfile::tempdir().unwrap();
    let sdir = tempfile::tempdir().unwrap();
    let settings = sdir.path().join("settings.json");
    setup(state.path(), &settings, "*", NARROWED);
    assert_eq!(run_verify(state.path(), None), 2);
}

#[test]
fn entry_missing_exits_2() {
    let state = tempfile::tempdir().unwrap();
    let sdir = tempfile::tempdir().unwrap();
    let settings = sdir.path().join("settings.json");
    setup(state.path(), &settings, "*", FOREIGN);
    assert_eq!(run_verify(state.path(), None), 2);
}

#[test]
fn command_drift_exits_2() {
    let state = tempfile::tempdir().unwrap();
    let sdir = tempfile::tempdir().unwrap();
    let settings = sdir.path().join("settings.json");
    setup(state.path(), &settings, "*", COMMAND_DRIFT); // same exe, changed --capture => command_drift
    assert_eq!(run_verify(state.path(), None), 2);
}

#[test]
fn baseline_absent_exits_3() {
    let state = tempfile::tempdir().unwrap(); // no hook-registration.json
    assert_eq!(run_verify(state.path(), None), 3);
}

#[test]
fn drift_emits_report_on_socket() {
    let sockdir = tempfile::tempdir().unwrap();
    let socket = sockdir.path().join("hook.sock");
    let l = UnixListener::bind(&socket).unwrap();
    let handle = std::thread::spawn(move || {
        // l is blocking by default; accept() returns as soon as the hook connects.
        match l.accept() {
            Ok((mut s, _)) => {
                let mut buf = String::new();
                let _ = s.read_to_string(&mut buf);
                buf
            }
            Err(_) => String::new(),
        }
    });

    let state = tempfile::tempdir().unwrap();
    let sdir = tempfile::tempdir().unwrap();
    let settings = sdir.path().join("settings.json");
    setup(state.path(), &settings, "*", NARROWED); // drift
    let code = run_verify(state.path(), Some(&socket));
    assert_eq!(code, 2);
    let got = handle.join().unwrap();
    assert!(
        got.contains("\"msg_type\":\"drift_report\""),
        "expected a drift_report emit, got: {got:?}"
    );
    assert!(
        got.contains("\"drift_kind\":\"matcher_drift\""),
        "drift_kind missing from emit: {got:?}"
    );
}
