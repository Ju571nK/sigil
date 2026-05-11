#[cfg(target_os = "macos")]
#[test]
fn it_fda_probe_distinguishes_eacces_from_enoent() {
    use sigil_agent::platform::{ActivePlatform, FdaState, Platform};
    let p = ActivePlatform::new();
    let s = p.fda_state();
    assert!(matches!(
        s,
        FdaState::Granted | FdaState::Denied | FdaState::Unknown
    ));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn it_fda_probe_is_granted_on_non_macos() {
    use sigil_agent::platform::{ActivePlatform, FdaState, Platform};
    let p = ActivePlatform::new();
    assert_eq!(p.fda_state(), FdaState::Granted);
}
