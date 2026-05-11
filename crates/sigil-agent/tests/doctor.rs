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
