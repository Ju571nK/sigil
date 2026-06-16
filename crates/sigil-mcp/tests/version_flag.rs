//! #161: `sigil-mcp --version` / `-V` print the package version and exit 0
//! (handled by `handle_version()` before the server starts), instead of
//! silently launching the MCP server on a bare flag.
use std::process::Command;

fn run(flag: &str) -> (i32, String) {
    let exe = env!("CARGO_BIN_EXE_sigil-mcp");
    let out = Command::new(exe).arg(flag).output().unwrap();
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (code, stdout)
}

#[test]
fn long_flag_prints_version_and_exits_0() {
    let (code, stdout) = run("--version");
    assert_eq!(code, 0, "expected exit 0, stdout={stdout:?}");
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version output {stdout:?} missing {}",
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn short_flag_prints_version_and_exits_0() {
    let (code, stdout) = run("-V");
    assert_eq!(code, 0, "expected exit 0, stdout={stdout:?}");
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version output {stdout:?} missing {}",
        env!("CARGO_PKG_VERSION")
    );
}
