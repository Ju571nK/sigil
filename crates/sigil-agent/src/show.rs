//! `sigil show ...` — print effective config, expanded paths, or live stats.

use crate::cli::ShowWhat;
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

}
