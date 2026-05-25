//! `sigil show ...` — print effective config, expanded paths, or live stats.

use crate::cli::ShowWhat;
#[cfg(feature = "operator-cli")]
use crate::control::PolicyStatusPayload;
#[cfg(feature = "operator-cli")]
use crate::control::RiskPayload;
#[cfg(feature = "operator-cli")]
use crate::control::TargetsPayload;
use crate::platform::ActivePlatform;
use sigil_core::policy::expand::{expand_per_user, EnvLookup};
use sigil_core::policy::{current_platform, defaults, merge};
use sigil_core::stats::StatsSnapshot;
use std::io::{self, Write};
use std::path::PathBuf;

pub fn run(
    what: ShowWhat,
    policy_override: Option<PathBuf>,
    events_dir_override: Option<PathBuf>,
) -> anyhow::Result<i32> {
    // `stats` talks to the running daemon over the control socket; it doesn't
    // touch the policy file, so handle it before the merge below.
    if let ShowWhat::Stats = what {
        return show_stats();
    }
    #[cfg(feature = "operator-cli")]
    if let ShowWhat::PolicyStatus = what {
        return show_policy_status();
    }
    #[cfg(not(feature = "operator-cli"))]
    let _ = events_dir_override;
    #[cfg(feature = "operator-cli")]
    if let ShowWhat::Targets = what {
        return show_targets();
    }
    #[cfg(feature = "operator-cli")]
    if let ShowWhat::Events {
        tail,
        follow,
        pretty,
    } = what
    {
        let events_dir = events_dir_override.unwrap_or_else(default_events_dir);
        return show_events(&events_dir, tail, follow, pretty);
    }
    #[cfg(feature = "operator-cli")]
    if let ShowWhat::Risk { tool, pretty } = what {
        return show_risk(tool, pretty);
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
        #[cfg(feature = "operator-cli")]
        ShowWhat::Events { .. } => unreachable!("handled above"),
        #[cfg(feature = "operator-cli")]
        ShowWhat::Risk { .. } => unreachable!("handled above"),
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

/// Mirror of `main.rs::default_events_dir`. Kept here so `show::run` can
/// resolve `--events-dir` without main.rs needing to plumb the default in for
/// every variant.
#[cfg(feature = "operator-cli")]
fn default_events_dir() -> PathBuf {
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        PathBuf::from("/var/log/sigil")
    } else {
        PathBuf::from(std::env::var_os("ProgramData").unwrap_or_default())
            .join("Sigil")
            .join("events")
    }
}

/// Snapshot or follow the agent's JSONL events. Wrapper around the
/// writer-parameterized `show_events_to` that targets stdout.
#[cfg(feature = "operator-cli")]
fn show_events(
    events_dir: &std::path::Path,
    tail: usize,
    follow: bool,
    pretty: bool,
) -> anyhow::Result<i32> {
    show_events_to(events_dir, tail, follow, pretty, &mut io::stdout().lock())
}

/// Core implementation. `w` lets tests capture output into a `Vec<u8>`.
#[cfg(feature = "operator-cli")]
fn show_events_to<W: Write>(
    events_dir: &std::path::Path,
    tail: usize,
    follow: bool,
    pretty: bool,
    w: &mut W,
) -> anyhow::Result<i32> {
    let Some(segment) = latest_segment(events_dir) else {
        writeln!(w, "(no events yet)")?;
        return Ok(0);
    };
    let backlog = read_last_n_lines(&segment, tail)?;
    for line in &backlog {
        if pretty {
            writeln!(w, "{}", format_pretty(line))?;
        } else {
            writeln!(w, "{line}")?;
        }
    }
    if !follow {
        return Ok(0);
    }
    run_follow(events_dir, &segment, &backlog, pretty)
}

/// Snapshot-mode entry point for integration tests. Public under the
/// `operator-cli` feature so `tests/show_events_e2e.rs` can call into it
/// without spawning the binary. Not part of the user-facing CLI surface.
#[cfg(feature = "operator-cli")]
pub fn show_events_for_test<W: Write>(
    events_dir: &std::path::Path,
    tail: usize,
    pretty: bool,
    w: &mut W,
) -> anyhow::Result<i32> {
    show_events_to(events_dir, tail, false, pretty, w)
}

/// 200 ms-polled follower over `events_dir`. Starts reading `initial_segment`
/// from the byte offset just past the backlog, and rotates to a new segment
/// when `latest_segment` changes. Exits cleanly on Ctrl-C.
#[cfg(feature = "operator-cli")]
fn run_follow(
    events_dir: &std::path::Path,
    initial_segment: &std::path::Path,
    backlog: &[String],
    pretty: bool,
) -> anyhow::Result<i32> {
    use std::io::{Read, Seek, SeekFrom};
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let events_dir = events_dir.to_path_buf();
    let mut current = initial_segment.to_path_buf();
    // Start at the byte offset of EOF as of the snapshot read: read the file's
    // current length, since `read_last_n_lines` already drained it.
    let mut offset: u64 = std::fs::metadata(&current).map(|m| m.len()).unwrap_or(0);
    let _ = backlog; // backlog already printed in snapshot phase
    rt.block_on(async move {
        let mut leftover: Vec<u8> = Vec::new();
        loop {
            // Cooperative cancellation: race the poll tick against ctrl_c.
            tokio::select! {
                _ = tokio::signal::ctrl_c() => return Ok::<i32, anyhow::Error>(0),
                _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
            }
            // Detect segment rotation.
            if let Some(latest) = latest_segment(&events_dir) {
                if latest != current {
                    current = latest;
                    offset = 0;
                    leftover.clear();
                }
            }
            // Read newly-appended bytes from `current` starting at `offset`.
            let mut file = match std::fs::File::open(&current) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let len = file.metadata()?.len();
            if len < offset {
                // File truncated/rotated under us — restart from 0.
                offset = 0;
                leftover.clear();
            }
            if len == offset {
                continue;
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut chunk = Vec::new();
            file.read_to_end(&mut chunk)?;
            offset = len;
            // Split on '\n' boundaries; carry any partial trailing line over to
            // the next tick.
            let mut buf = std::mem::take(&mut leftover);
            buf.extend_from_slice(&chunk);
            let mut start = 0usize;
            {
                // Stdout writes are sync; acceptable in a current_thread runtime
                // since they return immediately (kernel buffers the bytes).
                let stdout = std::io::stdout();
                let mut out = stdout.lock();
                for (i, b) in buf.iter().enumerate() {
                    if *b == b'\n' {
                        let line_bytes = &buf[start..i];
                        let line = String::from_utf8_lossy(line_bytes).into_owned();
                        let rendered = if pretty { format_pretty(&line) } else { line };
                        use std::io::Write;
                        out.write_all(rendered.as_bytes())?;
                        out.write_all(b"\n")?;
                        start = i + 1;
                    }
                }
            }
            if start < buf.len() {
                leftover = buf[start..].to_vec();
            }
        }
    })
}

/// Read the last `n` lines from `path`. Returns an empty `Vec` if the file is
/// missing. Handles files that do not end in a newline (the trailing partial
/// line is returned as a complete line). Buffers up to `n` lines in memory;
/// designed for the agent's small operational jsonl segments.
#[cfg(feature = "operator-cli")]
fn read_last_n_lines(path: &std::path::Path, n: usize) -> std::io::Result<Vec<String>> {
    use std::collections::VecDeque;
    use std::io::BufRead;
    if n == 0 {
        return Ok(Vec::new());
    }
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let reader = std::io::BufReader::new(file);
    let mut buf: VecDeque<String> = VecDeque::with_capacity(n);
    for line in reader.lines() {
        let line = line?;
        if buf.len() == n {
            buf.pop_front();
        }
        buf.push_back(line);
    }
    Ok(buf.into_iter().collect())
}

/// Map an `Evidence` variant to (kind_string, one-line summary) for the
/// `--pretty` renderer. `kind_string` matches the serde tag of the variant.
#[cfg(feature = "operator-cli")]
fn evidence_summary(e: &sigil_core::event::Evidence) -> (&'static str, String) {
    use sigil_core::event::Evidence;
    match e {
        Evidence::FileChange { after_hash, .. } => {
            let s = match after_hash {
                Some(h) if h.len() >= 12 => {
                    format!("blake3={}...{}", &h[..8], &h[h.len() - 4..])
                }
                Some(h) => format!("blake3={h}"),
                None => "blake3=(none)".to_string(),
            };
            ("file_change", s)
        }
        Evidence::Heartbeat {
            last_applied_policy_version,
            ..
        } => (
            "heartbeat",
            format!("policy_version={last_applied_policy_version}"),
        ),
        Evidence::ChannelStall {
            block_events_in_window,
            ..
        } => ("channel_stall", format!("drops={block_events_in_window}")),
        Evidence::PermissionMissing { resource, .. } => {
            ("permission_missing", format!("resource={resource}"))
        }
        Evidence::WatcherDegraded { from, to, .. } => ("watcher_degraded", format!("{from}->{to}")),
        Evidence::AgentDying { reason, .. } => ("agent_dying", format!("{reason:?}")),
        Evidence::RateLimitExceeded {
            count_dropped_in_window,
            ..
        } => (
            "rate_limit_exceeded",
            format!("dropped={count_dropped_in_window}"),
        ),
        Evidence::HostIdFingerprintDrift { .. } => ("host_id_fingerprint_drift", String::new()),
        Evidence::AgentJsonlForceGc {
            segments_deleted, ..
        } => (
            "agent_jsonl_force_gc",
            format!("deleted={segments_deleted}"),
        ),
        Evidence::SenderSkippedSegment { count, .. } => {
            ("sender_skipped_segment", format!("count={count}"))
        }
        Evidence::PolicySignatureInvalid { reason, .. } => {
            ("policy_signature_invalid", format!("reason={reason:?}"))
        }
        Evidence::PolicyReloaded { policy_version } => (
            "policy_reloaded",
            format!("policy_version={policy_version}"),
        ),
        Evidence::PolicyExpiredActive { policy_version, .. } => (
            "policy_expired_active",
            format!("policy_version={policy_version}"),
        ),
        Evidence::HostIdConflict { observed_status } => {
            ("host_id_conflict", format!("status={observed_status}"))
        }
        Evidence::AgentTooOld {
            observed_status, ..
        } => ("agent_too_old", format!("status={observed_status}")),
        Evidence::CertExpired { .. } => ("cert_expired", String::new()),
        Evidence::TlsFailure { reason } => ("tls_failure", format!("reason={reason}")),
        Evidence::EventUnprocessableLocal { .. } => ("event_unprocessable_local", String::new()),
        Evidence::ServerProtocolViolation { .. } => ("server_protocol_violation", String::new()),
        Evidence::SenderLagCritical { lag_events, .. } => {
            ("sender_lag_critical", format!("events={lag_events}"))
        }
        Evidence::AiGuardRiskAssessed { tool, bucket, .. } => (
            "ai_guard_risk_assessed",
            format!("tool={tool:?} bucket={bucket:?}"),
        ),
        Evidence::HostMetaSnapshot { .. } => ("host_meta_snapshot", String::new()),
    }
}

/// Render one JSONL line as a tab-separated one-liner: `<ts>\t<severity>\t<subject>\t<kind>\t<summary>`.
/// Unparseable lines pass through with a `! parse error:` marker plus the first
/// 80 chars of the offending line.
#[cfg(feature = "operator-cli")]
fn format_pretty(line: &str) -> String {
    let event: sigil_core::event::Event = match serde_json::from_str(line) {
        Ok(e) => e,
        Err(e) => {
            let preview: String = line.chars().take(80).collect();
            return format!("! parse error: {e}: {preview}");
        }
    };
    let ts = event
        .ts
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "<bad-ts>".to_string());
    let severity = match event.severity {
        sigil_core::event::Severity::Info => "info",
        sigil_core::event::Severity::Warn => "warn",
    };
    let subject = match &event.subject {
        sigil_core::event::Subject::Path { value } => value.display().to_string(),
        sigil_core::event::Subject::Self_ => "<self>".to_string(),
    };
    let (kind, summary) = evidence_summary(&event.evidence);
    format!("{ts}\t{severity}\t{subject}\t{kind}\t{summary}")
}

#[cfg(feature = "operator-cli")]
fn show_risk(tool: Option<String>, pretty: bool) -> anyhow::Result<i32> {
    let parsed = match tool.as_deref() {
        None => None,
        Some("claude-code") | Some("claude_code") => Some(sigil_core::event::AiTool::ClaudeCode),
        Some("codex") => Some(sigil_core::event::AiTool::Codex),
        Some("gemini") => Some(sigil_core::event::AiTool::Gemini),
        Some("cursor") => Some(sigil_core::event::AiTool::Cursor),
        Some(other) => {
            eprintln!("sigil show risk: unknown --tool '{other}' (expected: claude-code, codex, gemini, cursor)");
            return Ok(2);
        }
    };
    match crate::control_client::query(&crate::control::Request::Risk { tool: parsed }) {
        Ok(resp) => match resp.risk {
            Some(p) => {
                if pretty {
                    write_risk_pretty(&mut io::stdout().lock(), &p)?;
                } else {
                    let s = serde_json::to_string_pretty(&p)?;
                    println!("{s}");
                }
                Ok(0)
            }
            None => {
                eprintln!(
                    "sigil show risk: daemon returned no risk{}",
                    resp.error.map(|e| format!(": {e}")).unwrap_or_default()
                );
                Ok(1)
            }
        },
        Err(e) => {
            eprintln!("sigil show risk: {e}");
            Ok(1)
        }
    }
}

#[cfg(feature = "operator-cli")]
fn write_risk_pretty(w: &mut impl Write, p: &RiskPayload) -> io::Result<()> {
    if p.assessments.is_empty() {
        writeln!(w, "(no assessments yet)")?;
        return Ok(());
    }
    writeln!(w, "TOOL\tSCOPE\tSCORE\tBUCKET\tREASONS\tLAST_ASSESSED")?;
    for s in &p.assessments {
        let scope_str = match &s.scope {
            sigil_core::event::AiGuardScope::UserGlobal => "user-global".to_string(),
            sigil_core::event::AiGuardScope::Project { path } => {
                format!("project:{}", path.display())
            }
            sigil_core::event::AiGuardScope::Application { app } => {
                format!("application:{app}")
            }
        };
        let tool_str = match s.tool {
            sigil_core::event::AiTool::ClaudeCode => "claude-code",
            sigil_core::event::AiTool::Codex => "codex",
            sigil_core::event::AiTool::ClaudeDesktop => "claude-desktop",
            sigil_core::event::AiTool::ContinueDev => "continue-dev",
            sigil_core::event::AiTool::Gemini => "gemini",
            sigil_core::event::AiTool::Cursor => "cursor",
        };
        // Use the serde wire string (snake_case) rather than Debug. Robust
        // against future multi-word AiGuardBucket variants (e.g., "very_high")
        // where Debug would emit "Veryhigh" but the SIEM filter expects
        // "very_high".
        let bucket_str = serde_json::to_string(&s.bucket)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        writeln!(
            w,
            "{}\t{}\t{:.1}\t{}\t{}\t{}",
            tool_str, scope_str, s.score, bucket_str, s.reasons_count, s.last_assessed_ts
        )?;
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

    #[cfg(feature = "operator-cli")]
    #[test]
    fn latest_segment_returns_none_for_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(latest_segment(dir.path()).is_none());
    }

    #[cfg(feature = "operator-cli")]
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

    #[cfg(feature = "operator-cli")]
    #[test]
    fn latest_segment_returns_none_when_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("definitely-not-here");
        assert!(latest_segment(&missing).is_none());
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn read_last_n_lines_returns_empty_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no.jsonl");
        let out = read_last_n_lines(&missing, 5).unwrap();
        assert!(out.is_empty());
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn read_last_n_lines_returns_at_most_n() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        let mut s = String::new();
        for i in 0..50 {
            s.push_str(&format!("line-{i}\n"));
        }
        std::fs::write(&p, s).unwrap();
        let out = read_last_n_lines(&p, 5).unwrap();
        assert_eq!(out.len(), 5);
        assert_eq!(out[0], "line-45");
        assert_eq!(out[4], "line-49");
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn read_last_n_lines_handles_no_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        std::fs::write(&p, "a\nb\nc").unwrap();
        let out = read_last_n_lines(&p, 10).unwrap();
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn read_last_n_lines_n_zero_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.jsonl");
        std::fs::write(&p, "a\nb\n").unwrap();
        let out = read_last_n_lines(&p, 0).unwrap();
        assert!(out.is_empty());
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn format_pretty_renders_file_change_with_blake3_summary() {
        use sigil_core::event::{
            Event, Evidence, EvidenceQuality, FileChangeKind, Severity, SourceKind, Subject,
            SCHEMA_VERSION,
        };
        use std::path::PathBuf;
        use time::OffsetDateTime;
        let ev = Event {
            schema_version: SCHEMA_VERSION,
            event_id: uuid::Uuid::nil(),
            ts: OffsetDateTime::from_unix_timestamp(1747218181).unwrap(),
            host_id: "h".into(),
            agent_version: "0".into(),
            severity: Severity::Warn,
            source: SourceKind::FileSystem,
            subject: Subject::Path {
                value: PathBuf::from("/etc/shadow"),
            },
            evidence: Evidence::FileChange {
                change_kind: FileChangeKind::Modified,
                before_hash: None,
                after_hash: Some(
                    "ab12345678901234567890123456789012345678901234567890123456cdef1234".into(),
                ),
                recheck_hash: None,
                rename_from: None,
                size_after: Some(42),
                evidence_quality: EvidenceQuality::Definitive,
            },
            target_id: Some("etc-shadow".into()),
        };
        let line = serde_json::to_string(&ev).unwrap();
        let out = format_pretty(&line);
        // Tab-separated, 5 columns.
        let cols: Vec<&str> = out.split('\t').collect();
        assert_eq!(cols.len(), 5, "expected 5 tab-separated columns: {out}");
        assert_eq!(cols[1], "warn");
        assert_eq!(cols[2], "/etc/shadow");
        assert_eq!(cols[3], "file_change");
        assert_eq!(cols[4], "blake3=ab123456...1234");
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn format_pretty_renders_heartbeat_with_policy_version() {
        use sigil_core::event::{Event, Evidence, Severity, SourceKind, Subject, SCHEMA_VERSION};
        use std::collections::BTreeMap;
        use time::OffsetDateTime;
        let ev = Event {
            schema_version: SCHEMA_VERSION,
            event_id: uuid::Uuid::nil(),
            ts: OffsetDateTime::from_unix_timestamp(1747218181).unwrap(),
            host_id: "h".into(),
            agent_version: "0".into(),
            severity: Severity::Info,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::Heartbeat {
                uptime_s: 0,
                is_final: false,
                channel_stall_events_total: 0,
                events_emitted_total: 0,
                events_by_kind: BTreeMap::new(),
                hash_p50_ms: 0,
                hash_p99_ms: 0,
                watcher_backend: "fsevents".into(),
                state_db_size_bytes: 0,
                last_log_rotation_ts: None,
                last_applied_policy_version: 7,
                policy_expired_active: false,
                jsonl_above_soft_floor: false,
            },
            target_id: None,
        };
        let line = serde_json::to_string(&ev).unwrap();
        let out = format_pretty(&line);
        let cols: Vec<&str> = out.split('\t').collect();
        assert_eq!(cols.len(), 5);
        assert_eq!(cols[1], "info");
        assert_eq!(cols[2], "<self>");
        assert_eq!(cols[3], "heartbeat");
        assert_eq!(cols[4], "policy_version=7");
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn format_pretty_passes_through_unparseable_lines_with_marker() {
        let out = format_pretty("{not json");
        assert!(
            out.starts_with("! parse error:"),
            "expected parse error marker, got: {out}"
        );
        assert!(out.contains("{not json"));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn format_pretty_truncates_long_unparseable_preview_to_80() {
        let long = "X".repeat(200);
        let out = format_pretty(&long);
        assert!(out.starts_with("! parse error:"));
        // 80-char preview boundary somewhere in the output.
        let preview_chunk_count = out.matches('X').count();
        assert_eq!(
            preview_chunk_count, 80,
            "preview should be truncated to 80 X's, got {preview_chunk_count}"
        );
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn write_risk_pretty_renders_header_and_row() {
        use crate::control::{RiskPayload, RiskSummary};
        use sigil_core::event::{AiGuardBucket, AiGuardScope, AiTool};
        let payload = RiskPayload {
            assessments: vec![RiskSummary {
                tool: AiTool::ClaudeCode,
                scope: AiGuardScope::UserGlobal,
                score: 3.5,
                bucket: AiGuardBucket::Medium,
                reasons_count: 2,
                last_assessed_ts: "2026-05-16T06:00:00Z".into(),
            }],
        };
        let mut buf = Vec::new();
        write_risk_pretty(&mut buf, &payload).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.starts_with("TOOL\tSCOPE\tSCORE\tBUCKET\tREASONS\tLAST_ASSESSED\n"));
        assert!(
            out.contains("claude-code\tuser-global\t3.5\tmedium\t2\t2026-05-16T06:00:00Z"),
            "got: {out}"
        );
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn write_risk_pretty_empty_prints_sentinel() {
        use crate::control::RiskPayload;
        let payload = RiskPayload {
            assessments: vec![],
        };
        let mut buf = Vec::new();
        write_risk_pretty(&mut buf, &payload).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("(no assessments yet)"),
            "expected sentinel, got: {out}"
        );
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn write_risk_pretty_renders_project_scope() {
        use crate::control::{RiskPayload, RiskSummary};
        use sigil_core::event::{AiGuardBucket, AiGuardScope, AiTool};
        let payload = RiskPayload {
            assessments: vec![RiskSummary {
                tool: AiTool::Codex,
                scope: AiGuardScope::Project {
                    path: std::path::PathBuf::from("/Users/alice/repo/.claude"),
                },
                score: 8.0,
                bucket: AiGuardBucket::Critical,
                reasons_count: 5,
                last_assessed_ts: "2026-05-16T06:01:00Z".into(),
            }],
        };
        let mut buf = Vec::new();
        write_risk_pretty(&mut buf, &payload).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("codex\tproject:/Users/alice/repo/.claude\t8.0\tcritical\t5\t"),
            "got: {out}"
        );
    }
}
