//! `andeda doctor` — startup diagnostics, prints a formatted report.

use crate::platform::{ActivePlatform, FdaState, Platform};
use andeda_core::policy::expand::{expand_per_user, EnvLookup};
use andeda_core::policy::{current_platform, defaults, merge};
use std::path::PathBuf;

pub fn run(policy_override: Option<PathBuf>) -> i32 {
    let plat = ActivePlatform::new();
    let mut warn_count = 0;
    let mut error_count = 0;

    println!("ANDEDA doctor {}", env!("CARGO_PKG_VERSION"));
    println!("─────────────────────────────────────────────");

    let user_doc = match policy_override.as_ref() {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(yaml) => match andeda_core::policy::parse(&yaml) {
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
        .filter(|t| matches!(t.tier, andeda_core::policy::Tier::Critical))
        .count();
    let count_standard = effective.targets.len() - count_critical;
    println!(
        "[OK]   effective targets: {} (critical: {}, standard: {})",
        effective.targets.len(),
        count_critical,
        count_standard,
    );

    let users = andeda_core::policy::expand::UserEnumerator::list(&plat);
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
    match andeda_core::state::HashCache::open(&state_db_path) {
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
        PathBuf::from("/var/lib/andeda/state.db")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/andeda/state.db")
    }
    #[cfg(target_os = "windows")]
    {
        std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap_or_default())
            .join("Andeda/state.db")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/tmp/andeda-state.db")
    }
}
