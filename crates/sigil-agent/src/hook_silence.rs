//! #107 — hook-activity silence detection: in-memory per-agent activity record
//! and the pure silence-decision rule. The detector lives in the daemon (not the
//! tamperable hook); see the silence_task module for the periodic driver.

use parking_lot::Mutex;
use sigil_core::event::{AiTool, Confidence};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// Per-(agent,uid) activity, updated by the listeners on each observed hook event.
#[derive(Debug, Clone, PartialEq)]
pub struct ActivityRecord {
    pub last_hook_event_at: OffsetDateTime,
    pub last_emitted_at: Option<OffsetDateTime>,
    pub episode_open: bool,
}

/// Shared, in-memory only: empty on daemon start, so no agent is "expected"
/// until its hook fires again → no false alarm across a restart.
pub type ActivityMap = Arc<Mutex<HashMap<(AiTool, u32), ActivityRecord>>>;

pub fn new_map() -> ActivityMap {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Update at receive in the listeners — BEFORE the lossy `try_send` — so a
/// dropped-on-backpressure observation never becomes false silence. A fresh
/// hook event also closes any open silence episode.
pub fn record_hook_event(map: &ActivityMap, agent: AiTool, uid: u32, now: OffsetDateTime) {
    let mut g = map.lock();
    let r = g.entry((agent, uid)).or_insert(ActivityRecord {
        last_hook_event_at: now,
        last_emitted_at: None,
        episode_open: false,
    });
    r.last_hook_event_at = now;
    r.episode_open = false;
}

/// Window W (silence threshold) and horizon H (expectation decay).
#[derive(Debug, Clone, Copy)]
pub struct SilenceCfg {
    pub window: Duration,
    pub horizon: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    pub silent: bool,
    pub confidence: Confidence,
}

/// Pure, wall-clock silence rule. `session_active` is the (weak, spoofable)
/// filesystem probe result, supplied by the caller.
pub fn decide(
    r: &ActivityRecord,
    session_active: bool,
    now: OffsetDateTime,
    cfg: &SilenceCfg,
) -> Verdict {
    let since = now - r.last_hook_event_at;
    // `since >= ZERO` clamps a future last_hook_event_at (clock skew) to "not silent".
    let expected = since >= Duration::ZERO && since <= cfg.horizon;
    let silent = expected && session_active && since > cfg.window;
    Verdict {
        silent,
        confidence: Confidence::Low,
    }
}

/// Runtime caps for the capped session-directory scan.
#[derive(Debug, Clone, Copy)]
pub struct ProbeCapRt {
    pub max_entries: usize,
    pub max_depth: usize,
    pub budget: std::time::Duration,
}

/// Result of a single capped directory scan.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub active: bool,
    pub last_activity_at: Option<OffsetDateTime>,
    pub probe_kind: String,
    /// blake3 hash of the matched path — never the raw path.
    pub path_hash: Option<String>,
    pub probe_error: Option<String>,
    pub scan_truncated: bool,
}

/// Raw output of `newest_mtime_capped`.
#[derive(Debug)]
pub(crate) struct ScanOut {
    pub newest: Option<(OffsetDateTime, PathBuf)>,
    pub truncated: bool,
}

/// Capped, bounded-depth scan for the newest *file* mtime under `root`. Bounds:
/// `max_depth` (subdirs pushed only while depth < max_depth), `max_entries`
/// (counts files visited; dirs are not counted), and `budget` (checked once per
/// directory dequeue — a secondary backstop, `max_entries` is the hard bound).
/// Follows symlinks (`metadata`), but the depth+entry caps bound any cycle. A
/// deliberately weak, spoofable activity oracle; see the spec threat model.
pub(crate) fn newest_mtime_capped(root: &Path, cap: &ProbeCapRt) -> ScanOut {
    let start = std::time::Instant::now();
    let mut seen = 0usize;
    let mut truncated = false;
    let mut newest: Option<(OffsetDateTime, PathBuf)> = None;
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if start.elapsed() > cap.budget {
            truncated = true;
            break;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            if seen >= cap.max_entries {
                truncated = true;
                break;
            }
            seen += 1;
            let md = match ent.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if md.is_dir() {
                if depth < cap.max_depth {
                    stack.push((ent.path(), depth + 1));
                }
                continue;
            }
            if let Ok(mt) = md.modified() {
                let ot: OffsetDateTime = mt.into();
                if newest.as_ref().map_or(true, |(n, _)| ot > *n) {
                    newest = Some((ot, ent.path()));
                }
            }
        }
        if seen >= cap.max_entries {
            truncated = true;
            break;
        }
    }
    ScanOut { newest, truncated }
}

/// Per-agent versioned allowlist of session/transcript roots, resolved under `home`.
/// An unknown agent → empty → never flagged.
pub fn session_dirs(agent: AiTool, home: &Path) -> Vec<PathBuf> {
    match agent {
        AiTool::Codex => vec![home.join(".codex/sessions")],
        AiTool::ClaudeCode => vec![home.join(".claude/projects")],
        _ => vec![],
    }
}

/// Canonical probe-kind label for a given agent.
pub fn probe_kind_for(agent: AiTool) -> &'static str {
    match agent {
        AiTool::Codex => "codex_sessions",
        AiTool::ClaudeCode => "claude_transcripts",
        _ => "none",
    }
}

fn hash_path(p: &Path) -> String {
    format!(
        "blake3:{}",
        blake3::hash(p.to_string_lossy().as_bytes()).to_hex()
    )
}

/// Probe candidate dirs; `probe_error` is set when NONE of the candidate dirs exists.
/// `last_activity_at` is the newest mtime found; the caller applies the activity window.
pub fn probe_dirs(kind: &str, dirs: &[PathBuf], cap: &ProbeCapRt) -> ProbeResult {
    let mut newest: Option<(OffsetDateTime, PathBuf)> = None;
    let mut truncated = false;
    let mut any_dir = false;
    for d in dirs {
        if !d.exists() {
            continue;
        }
        any_dir = true;
        let s = newest_mtime_capped(d, cap);
        truncated |= s.truncated;
        if let Some((ot, p)) = s.newest {
            if newest.as_ref().map_or(true, |(n, _)| ot > *n) {
                newest = Some((ot, p));
            }
        }
    }
    if !any_dir {
        return ProbeResult {
            active: false,
            last_activity_at: None,
            probe_kind: kind.into(),
            path_hash: None,
            probe_error: Some("session dir not found".into()),
            scan_truncated: false,
        };
    }
    let (la, ph) = match &newest {
        Some((ot, p)) => (Some(*ot), Some(hash_path(p))),
        None => (None, None),
    };
    ProbeResult {
        active: la.is_some(),
        last_activity_at: la,
        probe_kind: kind.into(),
        path_hash: ph,
        probe_error: None,
        scan_truncated: truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Duration, OffsetDateTime};

    fn cfg() -> SilenceCfg {
        SilenceCfg {
            window: Duration::hours(12),
            horizon: Duration::days(7),
        }
    }
    fn rec_at(base: OffsetDateTime) -> ActivityRecord {
        ActivityRecord {
            last_hook_event_at: base,
            last_emitted_at: None,
            episode_open: false,
        }
    }

    #[test]
    fn active_and_silent_within_horizon_is_silent_low() {
        let base = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let now = base + Duration::hours(13); // > W (12h), < H (7d)
        let v = decide(&rec_at(base), true, now, &cfg());
        assert!(v.silent);
        assert_eq!(v.confidence, sigil_core::event::Confidence::Low);
    }

    #[test]
    fn idle_session_is_not_silent() {
        let base = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let now = base + Duration::hours(13);
        assert!(!decide(&rec_at(base), false, now, &cfg()).silent); // session not active
    }

    #[test]
    fn tool_free_turn_within_window_is_not_silent() {
        let base = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let now = base + Duration::hours(3); // < W
        assert!(!decide(&rec_at(base), true, now, &cfg()).silent);
    }

    #[test]
    fn decayed_past_horizon_is_not_expected() {
        let base = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let now = base + Duration::days(8); // > H → not expected
        assert!(!decide(&rec_at(base), true, now, &cfg()).silent);
    }

    #[test]
    fn future_last_hook_clock_skew_is_not_silent() {
        let base = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let now = base - Duration::hours(1); // now < last_hook (skew)
        assert!(!decide(&rec_at(base), true, now, &cfg()).silent);
    }

    #[test]
    fn exactly_at_window_is_not_silent() {
        let base = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let now = base + Duration::hours(12); // since == W; strict `>` → not silent
        assert!(!decide(&rec_at(base), true, now, &cfg()).silent);
    }

    #[test]
    fn exactly_at_horizon_is_still_expected() {
        let base = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let now = base + Duration::days(7); // since == H (inclusive) AND > W → silent
        assert!(decide(&rec_at(base), true, now, &cfg()).silent);
    }

    #[test]
    fn record_hook_event_marks_seen_and_closes_episode() {
        use sigil_core::event::AiTool;
        let map = new_map();
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        map.lock().insert(
            (AiTool::Codex, 501),
            ActivityRecord {
                last_hook_event_at: now - Duration::days(1),
                last_emitted_at: Some(now - Duration::days(1)),
                episode_open: true,
            },
        );
        record_hook_event(&map, AiTool::Codex, 501, now);
        let g = map.lock();
        let r = g.get(&(AiTool::Codex, 501)).unwrap();
        assert_eq!(r.last_hook_event_at, now);
        assert!(!r.episode_open);
    }

    #[test]
    fn newest_mtime_capped_truncates_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            std::fs::write(dir.path().join(format!("f{i}.jsonl")), "x").unwrap();
        }
        let cap = ProbeCapRt {
            max_entries: 3,
            max_depth: 1,
            budget: std::time::Duration::from_millis(50),
        };
        let out = newest_mtime_capped(dir.path(), &cap);
        assert!(out.newest.is_some());
        assert!(out.truncated); // 10 files, cap 3
    }

    #[test]
    fn newest_mtime_capped_respects_max_depth() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("deep.jsonl"), "x").unwrap(); // only file is at depth 1
        let cap0 = ProbeCapRt {
            max_entries: 256,
            max_depth: 0,
            budget: std::time::Duration::from_millis(50),
        };
        assert!(newest_mtime_capped(dir.path(), &cap0).newest.is_none()); // depth 0 → subdir not entered
        let cap1 = ProbeCapRt {
            max_entries: 256,
            max_depth: 1,
            budget: std::time::Duration::from_millis(50),
        };
        assert!(newest_mtime_capped(dir.path(), &cap1).newest.is_some()); // depth 1 → deep.jsonl found
    }

    #[test]
    fn session_dirs_unknown_agent_is_empty() {
        assert!(session_dirs(AiTool::ContinueDev, std::path::Path::new("/home/u")).is_empty());
    }

    #[test]
    fn session_dirs_known_agents_resolve_under_home() {
        let home = std::path::Path::new("/home/u");
        assert_eq!(
            session_dirs(AiTool::Codex, home),
            vec![home.join(".codex/sessions")]
        );
        assert_eq!(
            session_dirs(AiTool::ClaudeCode, home),
            vec![home.join(".claude/projects")]
        );
    }

    #[test]
    fn probe_dirs_hashes_path_never_raw_and_sets_active() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s.jsonl"), "x").unwrap();
        let cap = ProbeCapRt {
            max_entries: 256,
            max_depth: 3,
            budget: std::time::Duration::from_millis(50),
        };
        let pr = probe_dirs("codex_sessions", &[dir.path().to_path_buf()], &cap);
        assert!(pr.active);
        assert!(pr.last_activity_at.is_some());
        assert!(pr.path_hash.as_ref().unwrap().starts_with("blake3:"));
        let raw = dir.path().display().to_string();
        assert!(!format!("{pr:?}").contains(&raw)); // raw path never retained in the struct
        assert!(pr.probe_error.is_none());
    }

    #[test]
    fn probe_dirs_missing_dir_reports_error() {
        let cap = ProbeCapRt {
            max_entries: 8,
            max_depth: 1,
            budget: std::time::Duration::from_millis(50),
        };
        let pr = probe_dirs(
            "codex_sessions",
            &[std::path::PathBuf::from("/no/such/dir/xyz")],
            &cap,
        );
        assert!(!pr.active);
        assert!(pr.probe_error.is_some());
        assert!(pr.path_hash.is_none());
    }
}
