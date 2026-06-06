//! #107 — hook-activity silence detection: in-memory per-agent activity record
//! and the pure silence-decision rule. The detector lives in the daemon (not the
//! tamperable hook); see the silence_task module for the periodic driver.

use parking_lot::Mutex;
use sigil_core::event::{AiTool, Confidence};
use std::collections::HashMap;
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
}
