//! `sigil show ...` — print effective config, expanded paths, or live stats.

use crate::cli::ShowWhat;
#[cfg(feature = "operator-cli")]
use crate::control::PolicyStatusPayload;
#[cfg(feature = "operator-cli")]
use crate::control::TargetsPayload;
use crate::platform::ActivePlatform;
use sigil_core::policy::expand::{expand_per_user, EnvLookup};
use sigil_core::policy::{current_platform, defaults, merge};
use sigil_core::stats::StatsSnapshot;
use std::io::{self, Write};
use std::path::PathBuf;

pub fn run(what: ShowWhat, policy_override: Option<PathBuf>) -> anyhow::Result<i32> {
    // `stats` talks to the running daemon over the control socket; it doesn't
    // touch the policy file, so handle it before the merge below.
    if let ShowWhat::Stats = what {
        return show_stats();
    }
    #[cfg(feature = "operator-cli")]
    if let ShowWhat::PolicyStatus = what {
        return show_policy_status();
    }
    #[cfg(feature = "operator-cli")]
    if let ShowWhat::Targets = what {
        return show_targets();
    }

    let user_doc = match policy_override.as_ref() {
        Some(p) => Some(sigil_core::policy::parse(&std::fs::read_to_string(p)?)?),
        None => None,
    };
    let effective = merge(defaults()?, user_doc, current_platform())?;

    match what {
        ShowWhat::Config => {
            println!("{}", serde_yaml::to_string(&effective.targets)?);
        }
        ShowWhat::Paths => {
            let plat = ActivePlatform::new();
            let users = sigil_core::policy::expand::UserEnumerator::list(&plat);
            let env = EnvLookup;
            for t in &effective.targets {
                println!("# {} ({:?})", t.id, t.tier);
                for path_template in &t.paths {
                    for r in expand_per_user(path_template, &users, &env) {
                        match r {
                            Ok(p) => println!("  {}", p.display()),
                            Err(e) => println!("  ! expand error: {e}"),
                        }
                    }
                }
            }
        }
        ShowWhat::Stats => unreachable!("handled above"),
        #[cfg(feature = "operator-cli")]
        ShowWhat::PolicyStatus => unreachable!("handled above"),
        #[cfg(feature = "operator-cli")]
        ShowWhat::Targets => unreachable!("handled above"),
    }
    Ok(0)
}

/// Connect to the running daemon's control socket, ask for `{"cmd":"stats"}`,
/// and print the snapshot. Returns exit code 1 (without erroring) if the
/// daemon can't be reached — the common case being "it isn't running".
fn show_stats() -> anyhow::Result<i32> {
    match crate::control_client::query(&crate::control::Request::Stats) {
        Ok(resp) => match resp.stats {
            Some(snap) => {
                write_stats(&mut io::stdout().lock(), &snap)?;
                Ok(0)
            }
            None => {
                eprintln!(
                    "sigil show stats: daemon returned no stats{}",
                    resp.error.map(|e| format!(": {e}")).unwrap_or_default()
                );
                Ok(1)
            }
        },
        Err(e) => {
            eprintln!("sigil show stats: {e}");
            Ok(1)
        }
    }
}

fn write_stats(w: &mut impl Write, s: &StatsSnapshot) -> io::Result<()> {
    writeln!(w, "events emitted total : {}", s.events_emitted_total)?;
    writeln!(w, "channel stalls       : {}", s.channel_stall_events_total)?;
    writeln!(
        w,
        "hash latency p50/p99 : {} ms / {} ms",
        s.hash_p50_ms, s.hash_p99_ms
    )?;
    if s.events_by_kind.is_empty() {
        writeln!(w, "events by kind       : (none yet)")?;
    } else {
        writeln!(w, "events by kind       :")?;
        for (kind, count) in &s.events_by_kind {
            writeln!(w, "  {kind:<24} {count}")?;
        }
    }
    Ok(())
}

#[cfg(feature = "operator-cli")]
fn show_policy_status() -> anyhow::Result<i32> {
    match crate::control_client::query(&crate::control::Request::PolicyStatus) {
        Ok(resp) => match resp.policy_status {
            Some(p) => {
                write_policy_status(&mut io::stdout().lock(), &p)?;
                Ok(0)
            }
            None => {
                eprintln!(
                    "sigil show policy-status: daemon returned no policy_status{}",
                    resp.error.map(|e| format!(": {e}")).unwrap_or_default()
                );
                Ok(1)
            }
        },
        Err(e) => {
            eprintln!("sigil show policy-status: {e}");
            Ok(1)
        }
    }
}

#[cfg(feature = "operator-cli")]
fn write_policy_status(w: &mut impl Write, p: &PolicyStatusPayload) -> io::Result<()> {
    writeln!(
        w,
        "last applied policy version : {}",
        p.last_applied_policy_version
    )?;
    let valid_until = p
        .active_envelope_valid_until
        .as_deref()
        .unwrap_or("(no envelope applied)");
    writeln!(w, "active envelope valid until : {valid_until}")?;
    writeln!(
        w,
        "policy expired              : {}",
        if p.policy_expired_active { "yes" } else { "no" }
    )?;
    Ok(())
}

#[cfg(feature = "operator-cli")]
fn show_targets() -> anyhow::Result<i32> {
    match crate::control_client::query(&crate::control::Request::Targets) {
        Ok(resp) => match resp.targets {
            Some(t) => {
                write_targets(&mut io::stdout().lock(), &t)?;
                Ok(0)
            }
            None => {
                eprintln!(
                    "sigil show targets: daemon returned no targets{}",
                    resp.error.map(|e| format!(": {e}")).unwrap_or_default()
                );
                Ok(1)
            }
        },
        Err(e) => {
            eprintln!("sigil show targets: {e}");
            Ok(1)
        }
    }
}

#[cfg(feature = "operator-cli")]
fn write_targets(w: &mut impl Write, t: &TargetsPayload) -> io::Result<()> {
    if t.targets.is_empty() {
        writeln!(w, "(no active targets)")?;
        return Ok(());
    }
    for target in &t.targets {
        writeln!(w, "{} ({:?})", target.id, target.tier)?;
        if target.globs.is_empty() {
            writeln!(w, "  (no globs)")?;
        } else {
            for g in &target.globs {
                writeln!(w, "  {g}")?;
            }
        }
    }
    Ok(())
}

/// Return the path of the lexicographically-largest `events-*.jsonl` file in
/// `events_dir`, or `None` if the directory is missing or contains no matching
/// segment. Lexicographic order is chronological for the agent's segment
/// naming convention (`events-YYYY-MM-DD[-NNN].jsonl`).
#[cfg(feature = "operator-cli")]
// Wired into `show_events` in a later task — keep `dead_code` quiet until then.
#[allow(dead_code)]
fn latest_segment(events_dir: &std::path::Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(events_dir).ok()?;
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.starts_with("events-") && n.ends_with(".jsonl"))
                .unwrap_or(false)
        })
        .max()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn write_stats_renders_counts_and_kinds() {
        let mut by_kind = BTreeMap::new();
        by_kind.insert("file_change".to_string(), 12u64);
        by_kind.insert("heartbeat".to_string(), 3u64);
        let snap = StatsSnapshot {
            events_emitted_total: 15,
            channel_stall_events_total: 0,
            events_by_kind: by_kind,
            hash_p50_ms: 2,
            hash_p99_ms: 9,
        };
        let mut buf = Vec::new();
        write_stats(&mut buf, &snap).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("events emitted total : 15"));
        assert!(out.contains("hash latency p50/p99 : 2 ms / 9 ms"));
        assert!(out.contains("file_change"));
        assert!(out.contains("heartbeat"));
        assert!(out.contains(" 12"));
    }

    #[test]
    fn write_stats_handles_empty_kinds() {
        let snap = StatsSnapshot {
            events_emitted_total: 0,
            channel_stall_events_total: 0,
            events_by_kind: BTreeMap::new(),
            hash_p50_ms: 0,
            hash_p99_ms: 0,
        };
        let mut buf = Vec::new();
        write_stats(&mut buf, &snap).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("(none yet)"));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn write_policy_status_renders_active_envelope() {
        let p = crate::control::PolicyStatusPayload {
            last_applied_policy_version: 3,
            active_envelope_valid_until: Some("2026-06-12T00:00:00Z".into()),
            policy_expired_active: false,
        };
        let mut buf = Vec::new();
        write_policy_status(&mut buf, &p).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("last applied policy version : 3"));
        assert!(out.contains("active envelope valid until : 2026-06-12T00:00:00Z"));
        assert!(out.contains("policy expired              : no"));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn write_policy_status_handles_no_envelope_and_expired() {
        let p = crate::control::PolicyStatusPayload {
            last_applied_policy_version: 0,
            active_envelope_valid_until: None,
            policy_expired_active: true,
        };
        let mut buf = Vec::new();
        write_policy_status(&mut buf, &p).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("active envelope valid until : (no envelope applied)"));
        assert!(out.contains("policy expired              : yes"));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn write_targets_renders_multiple_targets() {
        use crate::control::{TargetSummary, TargetsPayload};
        use sigil_core::policy::Tier;
        let payload = TargetsPayload {
            targets: vec![
                TargetSummary {
                    id: "etc-shadow".to_string(),
                    tier: Tier::Critical,
                    globs: vec!["/etc/shadow".to_string(), "/etc/gshadow".to_string()],
                },
                TargetSummary {
                    id: "ssh-config".to_string(),
                    tier: Tier::Standard,
                    globs: vec!["/etc/ssh/sshd_config".to_string()],
                },
            ],
        };
        let mut buf = Vec::new();
        write_targets(&mut buf, &payload).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("etc-shadow (Critical)"));
        assert!(out.contains("  /etc/shadow"));
        assert!(out.contains("  /etc/gshadow"));
        assert!(out.contains("ssh-config (Standard)"));
        assert!(out.contains("  /etc/ssh/sshd_config"));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn write_targets_handles_empty_list() {
        use crate::control::TargetsPayload;
        let payload = TargetsPayload { targets: vec![] };
        let mut buf = Vec::new();
        write_targets(&mut buf, &payload).unwrap();
        assert!(String::from_utf8(buf)
            .unwrap()
            .contains("(no active targets)"));
    }

    #[test]
    fn latest_segment_returns_none_for_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(latest_segment(dir.path()).is_none());
    }

    #[test]
    fn latest_segment_picks_lexicographically_largest_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events-2026-05-12.jsonl"), b"").unwrap();
        std::fs::write(dir.path().join("events-2026-05-14-001.jsonl"), b"").unwrap();
        std::fs::write(dir.path().join("events-2026-05-13.jsonl"), b"").unwrap();
        // Non-matching files are skipped.
        std::fs::write(dir.path().join("readme.txt"), b"").unwrap();
        std::fs::write(dir.path().join("events-foo.json"), b"").unwrap();
        let picked = latest_segment(dir.path()).unwrap();
        assert_eq!(
            picked.file_name().unwrap().to_str().unwrap(),
            "events-2026-05-14-001.jsonl"
        );
    }

    #[test]
    fn latest_segment_returns_none_when_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("definitely-not-here");
        assert!(latest_segment(&missing).is_none());
    }
}
