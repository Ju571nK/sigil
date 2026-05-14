//! `sigil doctor` — startup diagnostics, prints a formatted report.

use crate::platform::{ActivePlatform, FdaState, Platform};
use sigil_core::policy::expand::{expand_per_user, EnvLookup};
use sigil_core::policy::{current_platform, defaults, merge};
use std::path::PathBuf;

/// Result of a single doctor check: `(level, message)`. Free type so the new
/// Linux helpers don't have to thread `warn_count`/`error_count` themselves —
/// the main `run()` aggregates from the returned `Level`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CheckLevel {
    Ok,
    // `Info` is constructed by `check_control_socket_perms` and
    // `check_systemd_unit` (Tasks 11/12); silence dead_code in the interim.
    #[allow(dead_code)]
    Info,
    Warn,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CheckResult {
    pub(crate) level: CheckLevel,
    pub(crate) message: String,
}

impl CheckResult {
    pub(crate) fn ok(msg: impl Into<String>) -> Self {
        Self {
            level: CheckLevel::Ok,
            message: msg.into(),
        }
    }
    // `info` is called by check_control_socket_perms / check_systemd_unit
    // (Tasks 11/12); silence dead_code in the interim.
    #[allow(dead_code)]
    pub(crate) fn info(msg: impl Into<String>) -> Self {
        Self {
            level: CheckLevel::Info,
            message: msg.into(),
        }
    }
    pub(crate) fn warn(msg: impl Into<String>) -> Self {
        Self {
            level: CheckLevel::Warn,
            message: msg.into(),
        }
    }
}

pub fn run(policy_override: Option<PathBuf>) -> i32 {
    let plat = ActivePlatform::new();
    let mut warn_count = 0;
    let mut error_count = 0;

    println!("Sigil doctor {}", env!("CARGO_PKG_VERSION"));
    println!("─────────────────────────────────────────────");

    let user_doc = match policy_override.as_ref() {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(yaml) => match sigil_core::policy::parse(&yaml) {
                Ok(d) => Some(d),
                Err(e) => {
                    println!("[ERROR] policy parse failed: {e}");
                    error_count += 1;
                    None
                }
            },
            Err(e) => {
                println!("[ERROR] cannot read policy {}: {e}", p.display());
                error_count += 1;
                None
            }
        },
        None => None,
    };

    let defaults = match defaults() {
        Ok(d) => d,
        Err(e) => {
            println!("[ERROR] defaults parse failed: {e}");
            return 2;
        }
    };

    let effective = match merge(defaults, user_doc, current_platform()) {
        Ok(e) => e,
        Err(e) => {
            println!("[ERROR] policy merge failed: {e}");
            return 2;
        }
    };

    let count_critical = effective
        .targets
        .iter()
        .filter(|t| matches!(t.tier, sigil_core::policy::Tier::Critical))
        .count();
    let count_standard = effective.targets.len() - count_critical;
    println!(
        "[OK]   effective targets: {} (critical: {}, standard: {})",
        effective.targets.len(),
        count_critical,
        count_standard,
    );

    let users = sigil_core::policy::expand::UserEnumerator::list(&plat);
    println!("[OK]   enumerated users: {}", users.len());

    let env = EnvLookup;
    let mut total_paths = 0usize;
    for t in &effective.targets {
        for path_template in &t.paths {
            let results = expand_per_user(path_template, &users, &env);
            for r in results {
                match r {
                    Ok(p) => {
                        if !p.exists() {
                            println!(
                                "[WARN] target {}: path does not exist: {}",
                                t.id,
                                p.display()
                            );
                            warn_count += 1;
                        }
                        total_paths += 1;
                    }
                    Err(e) => {
                        println!("[WARN] target {}: expand error: {e}", t.id);
                        warn_count += 1;
                    }
                }
            }
        }
    }
    println!("[OK]   total expanded paths: {total_paths}");

    // Phase 2: show persisted host_id from state.db.
    let state_db_path = default_state_db_path();
    match sigil_core::state::HashCache::open(&state_db_path) {
        Ok(cache) => match cache.host_meta_get() {
            Ok(meta) => {
                let host_id_display = meta
                    .host_id
                    .clone()
                    .unwrap_or_else(|| "<not yet generated>".into());
                println!("[OK]   host_id: {host_id_display} (UUIDv4, persisted in state.db)");
            }
            Err(e) => {
                println!("[WARN] host_meta_get failed: {e}");
                warn_count += 1;
            }
        },
        Err(e) => {
            println!(
                "[WARN] state.db unavailable for host_id read: {e} (path: {})",
                state_db_path.display()
            );
            warn_count += 1;
        }
    }

    if plat.name() == "macos" {
        match plat.fda_state() {
            FdaState::Granted => println!("[OK]   Full Disk Access: granted"),
            FdaState::Denied => {
                println!("[WARN] Full Disk Access: NOT granted");
                println!("       remedy: System Settings → Privacy & Security → Full Disk Access");
                warn_count += 1;
            }
            FdaState::Unknown => {
                println!("[WARN] Full Disk Access: status unknown (TCC.db missing)");
                warn_count += 1;
            }
        }
    }

    println!("─────────────────────────────────────────────");
    if error_count > 0 {
        println!("{error_count} error(s); daemon will not start.");
        2
    } else if warn_count > 0 {
        println!("{warn_count} warning(s); daemon will start with reduced coverage.");
        1
    } else {
        println!("All checks passed.");
        0
    }
}

/// Default state.db path matching the daemon's runtime default. Mirrors
/// the convention used by the CLI when `--state-db` is not provided.
fn default_state_db_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/lib/sigil/state.db")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/sigil/state.db")
    }
    #[cfg(target_os = "windows")]
    {
        std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap_or_default())
            .join("Sigil/state.db")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/tmp/sigil-state.db")
    }
}

/// Parse a Unix `/etc/group`-formatted file and return the gid of `name`, if
/// present. Each line is `name:passwd:gid:userlist`; we tolerate comment and
/// malformed lines by skipping them. Free function (takes a path) so unit
/// tests can use a tempfile.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_group_gid_from(path: &std::path::Path, name: &str) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(4, ':');
        let n = parts.next()?;
        let _passwd = parts.next()?;
        let gid = parts.next()?;
        if n != name {
            continue;
        }
        if let Ok(g) = gid.parse::<u32>() {
            return Some(g);
        }
    }
    None
}

/// Check `/sys/fs/selinux/enforce`: `1` → enforcing (WARN with audit2allow
/// hint), `0` → permissive (OK), missing file → disabled (OK).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn check_selinux(enforce_path: &std::path::Path) -> CheckResult {
    match std::fs::read_to_string(enforce_path) {
        Ok(s) => match s.trim() {
            "1" => CheckResult::warn(
                "SELinux: enforcing (sigil_t context not yet shipped — \
                 run `audit2allow -a | grep sigil` if events stop)"
                    .to_string(),
            ),
            "0" => CheckResult::ok("SELinux: permissive".to_string()),
            other => CheckResult::warn(format!("SELinux: unexpected enforce value '{other}'")),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            CheckResult::ok("SELinux: disabled".to_string())
        }
        Err(e) => CheckResult::warn(format!("SELinux: state read failed: {e}")),
    }
}

/// Check that the control socket exists and is owned by `root:sigil` with mode
/// `0o660`. Returns `Info` (not Warn) when the socket is missing because that
/// just means the daemon isn't running — not a config error.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn check_control_socket_perms(
    socket_path: &std::path::Path,
    group_file: &std::path::Path,
) -> CheckResult {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::metadata(socket_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return CheckResult::info(format!(
                "control socket: not present at {} (daemon not running?)",
                socket_path.display()
            ));
        }
        Err(e) => {
            return CheckResult::warn(format!(
                "control socket: stat failed at {}: {e}",
                socket_path.display()
            ));
        }
    };
    let Some(expected_gid) = read_group_gid_from(group_file, "sigil") else {
        return CheckResult::warn(format!(
            "control socket: 'sigil' group not found in {} — \
             daemon cannot drop privs to the right gid",
            group_file.display()
        ));
    };
    let actual_uid = meta.uid();
    let actual_gid = meta.gid();
    let actual_mode = meta.mode() & 0o777;
    if actual_uid == 0 && actual_gid == expected_gid && actual_mode == 0o660 {
        return CheckResult::ok(format!(
            "control socket: root:sigil({expected_gid}) 0660"
        ));
    }
    CheckResult::warn(format!(
        "control socket perms: uid={actual_uid} gid={actual_gid} mode={actual_mode:o}; \
         expected uid=0 gid={expected_gid} mode=660"
    ))
}

/// Determine whether sigil's systemd unit is installed + active + enabled
/// without shelling out to `systemctl` (no D-Bus required, works in container
/// and chroot environments).
///
/// Inputs:
/// - `run_systemd_system_dir`: typically `/run/systemd/system`. Presence → host
///   is running systemd.
/// - `unit_file`: typically `/usr/lib/systemd/system/sigil.service`. Presence
///   → unit installed.
/// - `cgroup_procs`: typically
///   `/sys/fs/cgroup/system.slice/sigil.service/cgroup.procs`. Existing + a
///   non-empty first line → unit active.
/// - `wants_link`: typically
///   `/etc/systemd/system/multi-user.target.wants/sigil.service`. Presence
///   (symlink or plain file) → unit enabled.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn check_systemd_unit(
    run_systemd_system_dir: &std::path::Path,
    unit_file: &std::path::Path,
    cgroup_procs: &std::path::Path,
    wants_link: &std::path::Path,
) -> CheckResult {
    if !run_systemd_system_dir.exists() {
        return CheckResult::info(format!(
            "systemd: not detected at {} (skipping unit checks)",
            run_systemd_system_dir.display()
        ));
    }
    if !unit_file.exists() {
        return CheckResult::warn(format!(
            "systemd unit: sigil.service not installed (expected at {})",
            unit_file.display()
        ));
    }
    let active = std::fs::read_to_string(cgroup_procs)
        .map(|s| s.lines().next().map(|l| !l.trim().is_empty()).unwrap_or(false))
        .unwrap_or(false);
    // `try_exists` follows symlinks; symlink_metadata covers dangling-link case
    // (still treated as "enabled" — the symlink itself being there is what
    // `systemctl enable` produces).
    let enabled = wants_link.exists() || std::fs::symlink_metadata(wants_link).is_ok();
    let active_word = if active { "active" } else { "inactive" };
    let enabled_word = if enabled { "enabled" } else { "disabled" };
    let level = if active && enabled {
        CheckLevel::Ok
    } else {
        CheckLevel::Warn
    };
    CheckResult {
        level,
        message: format!("systemd unit: {active_word}, {enabled_word}"),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_group_gid_returns_some_for_matching_name() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("group");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "root:x:0:").unwrap();
        writeln!(f, "sigil:x:996:").unwrap();
        writeln!(f, "wheel:x:10:user1,user2").unwrap();
        assert_eq!(read_group_gid_from(&p, "sigil"), Some(996));
        assert_eq!(read_group_gid_from(&p, "root"), Some(0));
    }

    #[test]
    fn read_group_gid_returns_none_when_name_absent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("group");
        std::fs::write(&p, "root:x:0:\n").unwrap();
        assert_eq!(read_group_gid_from(&p, "sigil"), None);
    }

    #[test]
    fn read_group_gid_skips_malformed_and_comment_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("group");
        std::fs::write(
            &p,
            "# comment\nsigil:x:notanumber:\nsigil:x:42:\n",
        )
        .unwrap();
        // Skips the malformed entry and accepts the second `sigil:` line.
        assert_eq!(read_group_gid_from(&p, "sigil"), Some(42));
    }

    #[test]
    fn read_group_gid_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_group_gid_from(&dir.path().join("nope"), "sigil"), None);
    }

    #[test]
    fn check_selinux_returns_disabled_when_enforce_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enforce");
        let r = check_selinux(&p);
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.message.contains("disabled"), "{:?}", r);
    }

    #[test]
    fn check_selinux_returns_permissive_when_enforce_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enforce");
        std::fs::write(&p, "0").unwrap();
        let r = check_selinux(&p);
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.message.contains("permissive"), "{:?}", r);
    }

    #[test]
    fn check_selinux_returns_warn_when_enforce_is_one() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enforce");
        std::fs::write(&p, "1").unwrap();
        let r = check_selinux(&p);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.message.contains("enforcing"), "{:?}", r);
        assert!(
            r.message.contains("audit2allow"),
            "expected audit2allow hint, got {:?}",
            r
        );
    }

    #[test]
    fn check_control_socket_perms_returns_info_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("control.sock");
        let group_file = dir.path().join("group");
        std::fs::write(&group_file, "sigil:x:996:\n").unwrap();
        let r = check_control_socket_perms(&p, &group_file);
        assert_eq!(r.level, CheckLevel::Info);
        assert!(r.message.contains("not present"), "{:?}", r);
    }

    #[test]
    fn check_control_socket_perms_warns_when_group_missing_from_etc_group() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("control.sock");
        std::fs::write(&p, b"").unwrap();
        let group_file = dir.path().join("group");
        std::fs::write(&group_file, "root:x:0:\n").unwrap();
        let r = check_control_socket_perms(&p, &group_file);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.message.contains("'sigil' group"), "{:?}", r);
    }

    #[test]
    fn check_control_socket_perms_warns_when_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("control.sock");
        std::fs::write(&p, b"").unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o666);
        std::fs::set_permissions(&p, perm).unwrap();
        let group_file = dir.path().join("group");
        std::fs::write(&group_file, "sigil:x:996:\n").unwrap();
        let r = check_control_socket_perms(&p, &group_file);
        assert_eq!(r.level, CheckLevel::Warn);
        // Implementation formats actual mode with `{:o}` (no leading 0), so
        // assert on the bare octal digits.
        assert!(r.message.contains("666"), "{:?}", r);
        assert!(r.message.contains("expected"), "{:?}", r);
    }

    #[test]
    fn check_systemd_unit_skips_when_run_systemd_missing() {
        let dir = tempfile::tempdir().unwrap();
        // run_systemd does NOT exist
        let r = check_systemd_unit(
            &dir.path().join("run-systemd-system"),
            &dir.path().join("lib/systemd/system/sigil.service"),
            &dir.path().join("cgroup-procs"),
            &dir.path().join("etc-wants/sigil.service"),
        );
        assert_eq!(r.level, CheckLevel::Info);
        assert!(r.message.contains("not detected"), "{:?}", r);
    }

    #[test]
    fn check_systemd_unit_warns_when_unit_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let run_systemd = dir.path().join("run-systemd-system");
        std::fs::create_dir_all(&run_systemd).unwrap();
        let r = check_systemd_unit(
            &run_systemd,
            &dir.path().join("lib/systemd/system/sigil.service"),
            &dir.path().join("cgroup-procs"),
            &dir.path().join("etc-wants/sigil.service"),
        );
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.message.contains("not installed"), "{:?}", r);
    }

    #[test]
    fn check_systemd_unit_reports_active_enabled_when_all_signals_present() {
        let dir = tempfile::tempdir().unwrap();
        let run_systemd = dir.path().join("run-systemd-system");
        std::fs::create_dir_all(&run_systemd).unwrap();
        let unit_file = dir.path().join("sigil.service");
        std::fs::write(&unit_file, b"[Unit]\nDescription=sigil\n").unwrap();
        let cgroup_procs = dir.path().join("cgroup.procs");
        std::fs::write(&cgroup_procs, b"12345\n").unwrap();
        let wants_link = dir.path().join("wants/sigil.service");
        std::fs::create_dir_all(dir.path().join("wants")).unwrap();
        // Plain file is fine for the existence-only check.
        std::fs::write(&wants_link, b"").unwrap();
        let r = check_systemd_unit(&run_systemd, &unit_file, &cgroup_procs, &wants_link);
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.message.contains("active"), "{:?}", r);
        assert!(r.message.contains("enabled"), "{:?}", r);
    }

    #[test]
    fn check_systemd_unit_warns_when_cgroup_procs_empty() {
        let dir = tempfile::tempdir().unwrap();
        let run_systemd = dir.path().join("run-systemd-system");
        std::fs::create_dir_all(&run_systemd).unwrap();
        let unit_file = dir.path().join("sigil.service");
        std::fs::write(&unit_file, b"").unwrap();
        let cgroup_procs = dir.path().join("cgroup.procs");
        std::fs::write(&cgroup_procs, b"").unwrap();
        let wants_link = dir.path().join("wants-not-there");
        let r = check_systemd_unit(&run_systemd, &unit_file, &cgroup_procs, &wants_link);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.message.contains("inactive"), "{:?}", r);
        assert!(r.message.contains("disabled"), "{:?}", r);
    }
}
