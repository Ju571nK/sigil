//! `sigil doctor` — startup diagnostics, prints a formatted report.

use crate::platform::{ActivePlatform, FdaState, Platform};
use sigil_core::policy::expand::{expand_per_user, EnvLookup};
use sigil_core::policy::{current_platform, defaults, merge};
use std::path::Path;
use std::path::PathBuf;

/// Result of a single doctor check: `(level, message)`. Free type so the
/// Linux helpers don't have to thread `warn_count`/`error_count` themselves —
/// the main `run()` aggregates from the returned `Level`. Linux-only because
/// every consumer (`check_selinux`, `check_control_socket_perms`,
/// `check_systemd_unit`, `check_events_dir_perms`) is Linux-only.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CheckLevel {
    Ok,
    Info,
    Warn,
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CheckResult {
    pub(crate) level: CheckLevel,
    pub(crate) message: String,
}

#[cfg(target_os = "linux")]
impl CheckResult {
    pub(crate) fn ok(msg: impl Into<String>) -> Self {
        Self {
            level: CheckLevel::Ok,
            message: msg.into(),
        }
    }
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

/// `--verify-self` 진입점. 실행 중 바이너리를 manifest 와 대조.
/// 0 = 일치+검증OK, 비0 = 그 외(unavailable 포함).
pub fn verify_self(manifest: Option<std::path::PathBuf>) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            println!("[verify-self] cannot resolve current exe: {e}");
            return 1;
        }
    };
    verify_self_impl(
        &exe,
        manifest,
        sigil_core::manifest::SIGIL_BUILD_PUBKEYS,
        env!("SIGIL_BUILD_TARGET"),
    )
}

/// 테스트 가능한 코어: keyset + target 을 주입받음.
pub(crate) fn verify_self_impl(
    exe: &Path,
    manifest: Option<std::path::PathBuf>,
    keys: &[(&str, &str)],
    target: &str,
) -> i32 {
    if keys.is_empty() {
        println!("[verify-self] no build trust anchor compiled in this release (populated in a future signed release)");
        return 1;
    }
    let Some(mpath) = manifest else {
        println!("[verify-self] no build manifest given (--manifest); self-verify unavailable");
        return 1;
    };
    let text = match std::fs::read_to_string(&mpath) {
        Ok(s) => s,
        Err(e) => {
            println!(
                "[verify-self] cannot read manifest {}: {e}",
                mpath.display()
            );
            return 1;
        }
    };
    let signed: sigil_core::manifest::SignedBuildManifest = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            println!("[verify-self] manifest parse failed: {e}");
            return 1;
        }
    };
    let manifest = match sigil_core::manifest::verify_manifest_with_keys(&signed, keys) {
        Ok(m) => m,
        Err(e) => {
            println!("[verify-self] manifest verification failed: {e}");
            return 1;
        }
    };
    let bytes = match std::fs::read(exe) {
        Ok(b) => b,
        Err(e) => {
            println!(
                "[verify-self] cannot read own binary {}: {e}",
                exe.display()
            );
            return 1;
        }
    };
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let name = exe.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    match manifest.artifact(name, target) {
        None => {
            println!("[verify-self] no manifest entry for {name}/{target}");
            1
        }
        Some(e) if e.blake3 == hash => {
            println!(
                "[OK] verify-self: {name}/{target} matches manifest (blake3 {}…)",
                &hash[..16]
            );
            0
        }
        Some(e) => {
            println!(
                "[FAIL] verify-self: {name}/{target} hash mismatch (binary {}… != manifest {}…)",
                &hash[..16],
                &e.blake3[..16]
            );
            1
        }
    }
}

pub fn run(policy_override: Option<PathBuf>, state_db_override: Option<PathBuf>) -> i32 {
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

    let effective = match merge(defaults, user_doc, None, current_platform()) {
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
    let mut absent_paths = 0usize;
    for t in &effective.targets {
        for path_template in &t.paths {
            let results = expand_per_user(path_template, &users, &env);
            for r in results {
                match r {
                    Ok(p) => {
                        if !p.exists() {
                            // Expected on a personal machine: not every covered AI
                            // tool is installed, so its config file is simply
                            // absent. Informational — it must NOT gate the exit
                            // code or alarm a healthy setup (#161).
                            println!(
                                "[INFO] target {}: not present (no file at {})",
                                t.id,
                                p.display()
                            );
                            absent_paths += 1;
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
    if absent_paths > 0 {
        println!(
            "[INFO] {absent_paths} target path(s) absent (tool not installed — simply not watched)"
        );
    }

    // Phase 2: show persisted host_id from state.db. Honor the `--state-db`
    // override (matching `sigil show`); fall back to the default path.
    let state_db_path = state_db_override.unwrap_or_else(crate::runtime::default_state_db_path);
    if !state_db_path.exists() {
        // Fresh install: the daemon creates state.db on its first `sigil run`.
        // Absent-before-first-run is expected, not a degradation (#161) — so it
        // stays informational and does NOT gate the exit code.
        println!(
            "[INFO] state.db not yet present (created on first 'sigil run'): {}",
            state_db_path.display()
        );
    } else {
        match sigil_core::state::HashCache::open(&state_db_path) {
            Ok(cache) => match cache.host_meta_get() {
                Ok(meta) => {
                    let host_id_display = meta
                        .host_id
                        .clone()
                        .unwrap_or_else(|| "<not yet generated>".into());
                    println!("[OK]   host_id: {host_id_display} (UUIDv4, persisted in state.db)");
                    let rp_ver = meta.last_applied_rule_packs_version;
                    println!("[INFO] rule-pack bundle version: {rp_ver}");
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

    #[cfg(target_os = "linux")]
    {
        let checks = [
            check_selinux(std::path::Path::new("/sys/fs/selinux/enforce")),
            {
                // Resolve the SAME socket path the daemon/CLI use: root →
                // /var/run/sigil, non-root → the XDG/tmp fallback. Expect it to
                // be owned by our euid (root for a root install). A non-root
                // personal install therefore no longer warns about a root-owned
                // socket at a path it never binds (#178).
                let euid = unsafe { libc::geteuid() };
                check_control_socket_perms(
                    &crate::control::default_control_socket(),
                    std::path::Path::new("/etc/group"),
                    euid,
                )
            },
            check_systemd_unit(
                std::path::Path::new("/run/systemd/system"),
                std::path::Path::new("/usr/lib/systemd/system/sigil.service"),
                std::path::Path::new("/sys/fs/cgroup/system.slice/sigil.service/cgroup.procs"),
                std::path::Path::new("/etc/systemd/system/multi-user.target.wants/sigil.service"),
            ),
            check_events_dir_perms(
                std::path::Path::new("/var/log/sigil"),
                std::path::Path::new("/etc/group"),
            ),
        ];
        for r in checks {
            let prefix = match r.level {
                CheckLevel::Ok => "[OK]  ",
                CheckLevel::Info => "[INFO]",
                CheckLevel::Warn => {
                    warn_count += 1;
                    "[WARN]"
                }
            };
            println!("{prefix} {}", r.message);
        }
    }

    #[cfg(feature = "operator-cli")]
    {
        println!();
        println!("──────────────  AI Guard  ──────────────");
        match crate::control_client::query(&crate::control::Request::DoctorAiGuardReport) {
            Ok(resp) => match resp.doctor_ai_guard {
                Some(rep) => {
                    print_ai_guard_live(&rep);
                    if !rep.unknown_override_keys.is_empty() {
                        for k in &rep.unknown_override_keys {
                            println!("[WARN] rubric override ignored — unknown reason kind: '{k}'");
                            warn_count += 1;
                        }
                    }
                }
                None => {
                    println!(
                        "[INFO] daemon returned no AI Guard report; falling back to static rubric"
                    );
                    print_static_rubric(&effective);
                }
            },
            Err(_e) => {
                println!("[INFO] sigil agent not running on control socket; live AI Guard state unavailable");
                println!("       (printing static rubric from disk policy only)");
                print_static_rubric(&effective);
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

#[cfg(feature = "operator-cli")]
fn print_ai_guard_live(rep: &crate::control::DoctorAiGuardReport) {
    println!(
        "[OK]   active parsers: {} ({})",
        rep.parsers.len(),
        format_parsers_summary(&rep.parsers)
    );
    println!(
        "[OK]   discovered per-repo: continue={}, claude_code={}, codex={}",
        rep.per_repo.continue_dev, rep.per_repo.claude_code, rep.per_repo.codex
    );
    if rep.rule_packs.is_empty() {
        println!("[OK]   loaded rule packs: 0");
    } else {
        let ids: Vec<&str> = rep.rule_packs.iter().map(|p| p.id.as_str()).collect();
        println!(
            "[OK]   loaded rule packs: {} ({})",
            rep.rule_packs.len(),
            ids.join(", ")
        );
    }
    println!(
        "[OK]   ext-script watch: {} unique paths across {} parsers",
        rep.ext_scripts.unique_paths, rep.ext_scripts.parser_entries
    );
    if rep.latest_risk.is_empty() {
        println!("[INFO] latest risk: (no assessments yet)");
    } else {
        println!("[INFO] latest risk:");
        for r in &rep.latest_risk {
            let tool_str = match r.tool {
                sigil_core::event::AiTool::ClaudeCode => "claude_code",
                sigil_core::event::AiTool::Codex => "codex",
                sigil_core::event::AiTool::ClaudeDesktop => "claude_desktop",
                sigil_core::event::AiTool::ContinueDev => "continue_dev",
                sigil_core::event::AiTool::Gemini => "gemini",
                sigil_core::event::AiTool::Cursor => "cursor",
                sigil_core::event::AiTool::Antigravity => "antigravity",
                sigil_core::event::AiTool::Grok => "grok",
                sigil_core::event::AiTool::Other => "other",
            };
            let scope_str = match &r.scope {
                sigil_core::event::AiGuardScope::UserGlobal => "user_global".to_string(),
                sigil_core::event::AiGuardScope::Project { path } => {
                    format!("project:{}", path.display())
                }
                sigil_core::event::AiGuardScope::Application { app } => {
                    format!("application:{app}")
                }
            };
            let bucket_str = serde_json::to_string(&r.bucket)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            println!(
                "         {} / {}    score {:.1}  bucket={}   reasons={}",
                tool_str, scope_str, r.score, bucket_str, r.reasons_count
            );
        }
    }

    println!();
    println!("────────────  Effective Rubric  ────────────");
    println!("  {:<36}  weight", "kind_key");
    for entry in &rep.effective_rubric {
        let marker = if entry.overridden { " *" } else { "" };
        println!("  {:<36}  {:.1}{}", entry.kind_key, entry.weight, marker);
    }
    println!("  (* = operator override)");
}

#[cfg(feature = "operator-cli")]
fn format_parsers_summary(parsers: &[crate::control::ParserInfo]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for p in parsers {
        let key = match p.tool {
            sigil_core::event::AiTool::ClaudeCode => "claude_code",
            sigil_core::event::AiTool::Codex => "codex",
            sigil_core::event::AiTool::ClaudeDesktop => "claude_desktop",
            sigil_core::event::AiTool::ContinueDev => "continue_dev",
            sigil_core::event::AiTool::Gemini => "gemini",
            sigil_core::event::AiTool::Cursor => "cursor",
            sigil_core::event::AiTool::Antigravity => "antigravity",
            sigil_core::event::AiTool::Grok => "grok",
            sigil_core::event::AiTool::Other => "other",
        };
        *counts.entry(key.to_string()).or_insert(0) += 1;
    }
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in counts {
        if v == 1 {
            parts.push(k);
        } else {
            parts.push(format!("{k}:{v}"));
        }
    }
    parts.join(", ")
}

#[cfg(feature = "operator-cli")]
fn print_static_rubric(effective: &sigil_core::policy::EffectivePolicy) {
    use crate::ai_guard::rubric::Rubric;
    let rubric = Rubric::defaults().with_overrides(&effective.rubric_overrides);

    println!();
    println!("────────────  Effective Rubric (static)  ────────────");
    println!("  {:<36}  weight", "kind_key");
    let mut entries: Vec<(&'static str, f32, bool)> = rubric
        .weights
        .iter()
        .map(|(k, w)| (*k, *w, rubric.overridden.contains(k)))
        .collect();
    // Sort: weight DESC then kind_key alpha — matches Task 4's IPC ordering.
    entries.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(b.0))
    });
    for (k, w, overridden) in &entries {
        let marker = if *overridden { " *" } else { "" };
        println!("  {:<36}  {:.1}{}", k, w, marker);
    }
    println!("  (* = operator override)");

    if !rubric.unknown_override_keys.is_empty() {
        for k in &rubric.unknown_override_keys {
            println!("[WARN] rubric override ignored — unknown reason kind: '{k}'");
        }
    }
}

/// Parse a Unix `/etc/group`-formatted file and return the gid of `name`, if
/// present. Each line is `name:passwd:gid:userlist`; we tolerate comment and
/// malformed lines by skipping them. Free function (takes a path) so unit
/// tests can use a tempfile.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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

/// Check that the control socket exists, is root-owned, and is NOT world-accessible
/// (issue #4). The `sigil` group is informational only — the full root:sigil /
/// dedicated-user hardening is tracked separately (epic #10).
/// Returns `Info` (not Warn) when the socket is missing because that
/// just means the daemon isn't running — not a config error.
#[cfg(target_os = "linux")]
fn check_control_socket_perms(
    socket_path: &std::path::Path,
    group_file: &std::path::Path,
    expected_uid: u32,
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
    let sigil_gid = read_group_gid_from(group_file, "sigil");
    classify_socket_perms(
        &socket_path.display().to_string(),
        meta.uid(),
        meta.gid(),
        meta.mode() & 0o777,
        sigil_gid,
        expected_uid,
    )
}

/// Pure classifier (testable without a real owned file). The socket must be
/// owned by `expected_uid` (root for a root install, the invoking user for a
/// non-root personal install) and have no access bits for `other`. The
/// root:sigil group hardening (epic #10) applies only to the root deployment,
/// so the `sigil` group is reported but never required.
#[cfg(target_os = "linux")]
fn classify_socket_perms(
    path: &str,
    uid: u32,
    gid: u32,
    mode: u32,
    sigil_gid: Option<u32>,
    expected_uid: u32,
) -> CheckResult {
    if uid != expected_uid {
        let expected = if expected_uid == 0 {
            "root (uid 0)".to_string()
        } else {
            format!("uid {expected_uid}")
        };
        return CheckResult::warn(format!(
            "control socket: owner uid={uid}, expected {expected} at {path}"
        ));
    }
    if mode & 0o007 != 0 {
        return CheckResult::warn(format!(
            "control socket: world-accessible (mode {mode:o}); expected no access for 'other' \
             (e.g. 0660) at {path}"
        ));
    }
    let (owner, ownership) = if uid == 0 {
        let group = match sigil_gid {
            Some(g) if g == gid => format!("root:sigil({g})"),
            _ => format!("root:gid({gid})"),
        };
        (group, "root-owned")
    } else {
        (format!("uid({uid}):gid({gid})"), "user-owned")
    };
    CheckResult::ok(format!(
        "control socket: {owner} mode {mode:o} ({ownership}, not world-accessible)"
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
#[cfg(target_os = "linux")]
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
        .map(|s| {
            s.lines()
                .next()
                .map(|l| !l.trim().is_empty())
                .unwrap_or(false)
        })
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

/// Check that the agent's events_dir exists and has reasonable perms. The
/// agent writes as `sigil`; operators read via `sigil show events`, so we
/// accept `0o750` (group-read for sigil) or `0o755` (world-read). World-write
/// is always a WARN.
#[cfg(target_os = "linux")]
fn check_events_dir_perms(
    events_dir: &std::path::Path,
    group_file: &std::path::Path,
) -> CheckResult {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::metadata(events_dir) {
        Ok(m) => m,
        Err(_) => {
            return CheckResult::warn(format!("events dir: not found at {}", events_dir.display()));
        }
    };
    classify_events_dir_perms(
        &events_dir.display().to_string(),
        meta.is_dir(),
        meta.uid(),
        meta.mode() & 0o777,
        meta.gid(),
        read_group_gid_from(group_file, "sigil"),
    )
}

/// Pure classifier for the events dir (testable without a real dir). The dir must
/// be root-owned (mirrors the control-socket check); accepts 0750 (group-read for
/// sigil) or 0755 (world-read); world-write is always Warn; if the sigil group
/// exists, the dir gid must match it (#10). A non-root owner is a Warn even with
/// `root:sigil`-looking group/mode, since that owner can still mutate the dir (#60).
#[cfg(target_os = "linux")]
fn classify_events_dir_perms(
    path: &str,
    is_dir: bool,
    uid: u32,
    mode: u32,
    gid: u32,
    sigil_gid: Option<u32>,
) -> CheckResult {
    if !is_dir {
        return CheckResult::warn(format!("events dir: {path} exists but is not a directory"));
    }
    if uid != 0 {
        return CheckResult::warn(format!(
            "events dir owner: uid={uid}, expected root (uid 0) at {path}"
        ));
    }
    if mode & 0o002 != 0 {
        return CheckResult::warn(format!(
            "events dir perms: mode={mode:o} is world-writable at {path}"
        ));
    }
    if mode != 0o750 && mode != 0o755 {
        return CheckResult::warn(format!(
            "events dir perms: mode={mode:o}; expected 0750 or 0755 at {path}"
        ));
    }
    if let Some(g) = sigil_gid {
        if gid != g {
            return CheckResult::warn(format!(
                "events dir owner: gid={gid}; expected gid={g} (sigil group) at {path}"
            ));
        }
    }
    let group = match sigil_gid {
        Some(g) if g == gid => format!("root:sigil({g})"),
        _ => format!("gid({gid})"),
    };
    CheckResult::ok(format!("events dir: {group} mode 0{mode:o} at {path}"))
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
        std::fs::write(&p, "# comment\nsigil:x:notanumber:\nsigil:x:42:\n").unwrap();
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
        let r = check_control_socket_perms(&p, &group_file, 0);
        assert_eq!(r.level, CheckLevel::Info);
        assert!(r.message.contains("not present"), "{:?}", r);
    }

    #[test]
    fn classify_socket_ok_root_0660_with_sigil_group() {
        let r = classify_socket_perms("/run/sigil/control.sock", 0, 996, 0o660, Some(996), 0);
        assert_eq!(r.level, CheckLevel::Ok);
        assert!(r.message.contains("root:sigil(996)"), "{r:?}");
    }

    #[test]
    fn classify_socket_ok_root_0660_without_sigil_group() {
        // sigil group absent or gid mismatch → still OK (group is informational, epic #10).
        let r = classify_socket_perms("/run/sigil/control.sock", 0, 0, 0o660, None, 0);
        assert_eq!(r.level, CheckLevel::Ok, "{r:?}");
        assert!(r.message.contains("root-owned"), "{r:?}");
    }

    #[test]
    fn classify_socket_ok_root_0660_with_gid_mismatch() {
        // sigil group exists but the socket's gid differs → still Ok, labeled root:gid(N).
        let r = classify_socket_perms("/run/sigil/control.sock", 0, 999, 0o660, Some(996), 0);
        assert_eq!(r.level, CheckLevel::Ok, "{r:?}");
        assert!(r.message.contains("root:gid(999)"), "{r:?}");
        assert!(!r.message.contains("sigil"), "{r:?}");
    }

    #[test]
    fn classify_socket_ok_root_0600_is_not_world_accessible() {
        // 0600 (no group/other access) is stricter than 0660 → still Ok.
        let r = classify_socket_perms("/run/sigil/control.sock", 0, 0, 0o600, None, 0);
        assert_eq!(r.level, CheckLevel::Ok, "{r:?}");
    }

    #[test]
    fn classify_socket_warns_when_world_accessible() {
        let r = classify_socket_perms("/run/sigil/control.sock", 0, 0, 0o666, Some(996), 0);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.message.contains("world-accessible"), "{r:?}");
    }

    #[test]
    fn classify_socket_warns_when_owner_differs_from_expected() {
        // Root install expects uid 0; a non-root owner is a real warning.
        let r = classify_socket_perms("/run/sigil/control.sock", 1000, 1000, 0o660, Some(996), 0);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.message.contains("uid=1000"), "{r:?}");
        assert!(r.message.contains("expected root"), "{r:?}");
    }

    #[test]
    fn classify_socket_ok_nonroot_user_owned() {
        // #178 — non-root personal install: socket owned by the invoking user
        // (expected_uid = 1000) is Ok, labeled user-owned (no root expectation).
        let r = classify_socket_perms(
            "/tmp/sigil-1000/control.sock",
            1000,
            1000,
            0o600,
            None,
            1000,
        );
        assert_eq!(r.level, CheckLevel::Ok, "{r:?}");
        assert!(r.message.contains("user-owned"), "{r:?}");
        assert!(r.message.contains("uid(1000)"), "{r:?}");
    }

    #[test]
    fn classify_socket_nonroot_warns_when_owner_mismatch() {
        // #178 — non-root expects its own uid; a root-owned socket there is a
        // genuine mismatch, reported as "expected uid 1000" (not "expected root").
        let r = classify_socket_perms("/tmp/sigil-1000/control.sock", 0, 0, 0o600, None, 1000);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.message.contains("expected uid 1000"), "{r:?}");
    }

    #[test]
    fn classify_events_dir_ok_root_sigil_0750() {
        let r = classify_events_dir_perms("/var/log/sigil", true, 0, 0o750, 996, Some(996));
        assert_eq!(r.level, CheckLevel::Ok, "{r:?}");
        assert!(r.message.contains("root:sigil(996)"), "{r:?}");
    }
    #[test]
    fn classify_events_dir_ok_without_group_0755() {
        let r = classify_events_dir_perms("/var/log/sigil", true, 0, 0o755, 0, None);
        assert_eq!(r.level, CheckLevel::Ok, "{r:?}");
    }
    #[test]
    fn classify_events_dir_warn_not_root_owned() {
        // Owned by a non-root user but group=sigil mode=0750: must NOT pass as
        // root:sigil — the owner can still mutate the dir (#60).
        let r = classify_events_dir_perms("/var/log/sigil", true, 1000, 0o750, 996, Some(996));
        assert_eq!(r.level, CheckLevel::Warn, "{r:?}");
        assert!(r.message.contains("uid=1000"), "{r:?}");
        assert!(!r.message.contains("root:sigil"), "{r:?}");
    }
    #[test]
    fn classify_events_dir_warn_world_writable() {
        let r = classify_events_dir_perms("/var/log/sigil", true, 0, 0o757, 0, None);
        assert_eq!(r.level, CheckLevel::Warn, "{r:?}");
        assert!(r.message.contains("world-writable"), "{r:?}");
    }
    #[test]
    fn classify_events_dir_warn_group_mismatch() {
        let r = classify_events_dir_perms("/var/log/sigil", true, 0, 0o750, 0, Some(996));
        assert_eq!(r.level, CheckLevel::Warn, "{r:?}");
        assert!(r.message.contains("expected gid=996"), "{r:?}");
    }
    #[test]
    fn classify_events_dir_warn_not_a_dir() {
        let r = classify_events_dir_perms("/var/log/sigil", false, 0, 0o750, 0, None);
        assert_eq!(r.level, CheckLevel::Warn, "{r:?}");
        assert!(r.message.contains("not a directory"), "{r:?}");
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

    #[test]
    fn check_events_dir_perms_warns_when_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let group_file = dir.path().join("group");
        std::fs::write(&group_file, "sigil:x:996:\n").unwrap();
        let r = check_events_dir_perms(&missing, &group_file);
        assert_eq!(r.level, CheckLevel::Warn);
        assert!(r.message.contains("not found"), "{:?}", r);
    }

    #[test]
    fn check_events_dir_perms_warns_when_world_writable() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let ev = dir.path().join("events");
        std::fs::create_dir(&ev).unwrap();
        let mut perm = std::fs::metadata(&ev).unwrap().permissions();
        perm.set_mode(0o777);
        std::fs::set_permissions(&ev, perm).unwrap();
        let group_file = dir.path().join("group");
        std::fs::write(&group_file, "sigil:x:996:\n").unwrap();
        let r = check_events_dir_perms(&ev, &group_file);
        assert_eq!(r.level, CheckLevel::Warn);
        // A non-root owner is flagged before the mode (#60), so only a
        // root-owned tempdir (CI container jobs run as root) reaches the
        // world-writable message; a non-root runner sees the owner warning.
        if std::fs::metadata(&ev).unwrap().uid() == 0 {
            assert!(r.message.contains("777"), "{:?}", r);
        } else {
            assert!(r.message.contains("uid="), "{:?}", r);
        }
    }

    #[test]
    fn check_events_dir_perms_ok_for_0750() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let ev = dir.path().join("events");
        std::fs::create_dir(&ev).unwrap();
        let mut perm = std::fs::metadata(&ev).unwrap().permissions();
        perm.set_mode(0o750);
        std::fs::set_permissions(&ev, perm).unwrap();
        // Empty group file → `read_group_gid_from` returns None → the gid
        // ownership check inside `check_events_dir_perms` is skipped. We can't
        // chown the tempdir to a real `sigil` gid in a unit test, so this
        // isolates the mode check — but only when the dir is root-owned.
        let group_file = dir.path().join("group");
        std::fs::write(&group_file, "").unwrap();
        let r = check_events_dir_perms(&ev, &group_file);
        if std::fs::metadata(&ev).unwrap().uid() == 0 {
            assert_eq!(r.level, CheckLevel::Ok);
            assert!(r.message.contains("0750"), "{:?}", r);
        } else {
            // A non-root runner owns the tempdir, so the owner check warns (#60).
            assert_eq!(r.level, CheckLevel::Warn, "{r:?}");
            assert!(r.message.contains("uid="), "{:?}", r);
        }
    }
}

#[cfg(test)]
mod verify_self_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use sigil_core::manifest::{
        ArtifactEntry, BuildManifest, SignedBuildManifest, MANIFEST_SCHEMA_VERSION,
    };
    use sigil_core::policy::canonical::to_canonical_bytes;
    use std::io::Write;

    const TGT: &str = "x86_64-apple-darwin";

    fn keypair() -> (SigningKey, String) {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        let sk = SigningKey::from_bytes(&s);
        (
            sk.clone(),
            format!(
                "ed25519:{}",
                data_encoding::BASE64.encode(&sk.verifying_key().to_bytes())
            ),
        )
    }
    fn fixture(
        dir: &Path,
        sk: &SigningKey,
        key_id: &str,
        exe_name: &str,
        exe_body: &[u8],
        entry_hash: Option<String>,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let exe = dir.join(exe_name);
        {
            let mut f = std::fs::File::create(&exe).unwrap();
            f.write_all(exe_body).unwrap();
        }
        let blake3 = entry_hash.unwrap_or_else(|| blake3::hash(exe_body).to_hex().to_string());
        let m = BuildManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            git_sha: "s".into(),
            run_url: "".into(),
            built_at: time::macros::datetime!(2026-05-24 0:00 UTC),
            artifacts: vec![ArtifactEntry {
                name: exe_name.into(),
                target: TGT.into(),
                blake3,
            }],
        };
        let sig = sk.sign(&to_canonical_bytes(&m).unwrap());
        let signed = SignedBuildManifest {
            manifest: m,
            signature: data_encoding::BASE64.encode(&sig.to_bytes()),
            signing_pubkey_id: key_id.into(),
        };
        let mpath = dir.join("manifest.json");
        std::fs::write(&mpath, serde_json::to_vec_pretty(&signed).unwrap()).unwrap();
        (exe, mpath)
    }

    #[test]
    fn match_exits_zero() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, entry) = keypair();
        let (exe, mpath) = fixture(dir.path(), &sk, "bk", "sigil", b"the-binary", None);
        let keys = [("bk", entry.as_str())];
        assert_eq!(verify_self_impl(&exe, Some(mpath), &keys, TGT), 0);
    }
    #[test]
    fn mutated_binary_exits_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, entry) = keypair();
        let good = blake3::hash(b"the-binary").to_hex().to_string();
        let (exe, mpath) = fixture(dir.path(), &sk, "bk", "sigil", b"TAMPERED", Some(good));
        let keys = [("bk", entry.as_str())];
        assert_ne!(verify_self_impl(&exe, Some(mpath), &keys, TGT), 0);
    }
    #[test]
    fn no_entry_for_target_exits_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, entry) = keypair();
        let (exe, mpath) = fixture(dir.path(), &sk, "bk", "sigil", b"x", None);
        let keys = [("bk", entry.as_str())];
        assert_ne!(
            verify_self_impl(&exe, Some(mpath), &keys, "aarch64-unknown-linux-gnu"),
            0
        );
    }
    #[test]
    fn tampered_signature_exits_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _entry) = keypair();
        let (exe, mpath) = fixture(dir.path(), &sk, "bk", "sigil", b"x", None);
        let (_sk2, other) = keypair();
        let keys = [("bk", other.as_str())];
        assert_ne!(verify_self_impl(&exe, Some(mpath), &keys, TGT), 0);
    }
    #[test]
    fn empty_anchor_exits_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, _e) = keypair();
        let (exe, mpath) = fixture(dir.path(), &sk, "bk", "sigil", b"x", None);
        assert_ne!(verify_self_impl(&exe, Some(mpath), &[], TGT), 0);
    }
    #[test]
    fn no_manifest_exits_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let (_sk, entry) = keypair();
        let exe = dir.path().join("sigil");
        std::fs::write(&exe, b"x").unwrap();
        let keys = [("bk", entry.as_str())];
        assert_ne!(verify_self_impl(&exe, None, &keys, TGT), 0);
    }
}
