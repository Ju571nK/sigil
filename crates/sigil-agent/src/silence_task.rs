//! #107 — periodic driver for hook-activity silence detection. Opt-in per agent;
//! probes each expected agent's session dir, runs the pure `decide()` rule, and
//! emits one low-confidence `PossibleHookActivitySilent` per silence episode.

use crate::hook_silence::{decide, ActivityMap, ProbeCapRt, ProbeResult, SilenceCfg};
use crate::state_task::CommittableEvent;
use sigil_core::event::{
    AiTool, Confidence, Event, Evidence, PossibleHookActivitySilentEvidence, Severity, SourceKind,
    Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use std::path::PathBuf;
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct SilenceTaskCtx {
    pub host_id: String,
    pub map: ActivityMap,
    pub enabled: Vec<AiTool>,
    pub window: Duration,
    pub horizon: Duration,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    pub now_fn: Box<dyn Fn() -> OffsetDateTime + Send + Sync>,
    pub probe_fn: Box<dyn Fn(AiTool, u32) -> ProbeResult + Send + Sync>,
}

pub async fn evaluate(ctx: &SilenceTaskCtx) {
    let now = (ctx.now_fn)();
    let cfg = SilenceCfg {
        window: ctx.window,
        horizon: ctx.horizon,
    };
    // Snapshot keys for opted-in agents; do not hold the lock across probe/emit.
    let keys: Vec<(AiTool, u32)> = {
        let g = ctx.map.lock();
        g.keys()
            .filter(|(a, _)| ctx.enabled.contains(a))
            .cloned()
            .collect()
    };
    for key in keys {
        let (agent, uid) = key;
        let Some(record) = ctx.map.lock().get(&key).cloned() else {
            continue;
        };
        let probe = (ctx.probe_fn)(agent, uid);
        // window applied here (single place): session active = recent enough mtime.
        let session_active = probe.active
            && probe.last_activity_at.is_some_and(|la| {
                let d = now - la;
                d >= Duration::ZERO && d <= ctx.window
            });
        if decide(&record, session_active, now, &cfg).silent && !record.episode_open {
            let ev = Event {
                schema_version: SCHEMA_VERSION,
                event_id: Uuid::now_v7(),
                ts: now,
                host_id: ctx.host_id.clone(),
                agent_version: AGENT_VERSION.to_string(),
                severity: Severity::Warn,
                source: SourceKind::Agent,
                subject: Subject::Self_,
                evidence: Evidence::PossibleHookActivitySilent(
                    PossibleHookActivitySilentEvidence {
                        agent,
                        uid: Some(uid),
                        last_hook_seen_at: record.last_hook_event_at,
                        last_session_activity_at: probe.last_activity_at,
                        window_secs: ctx.window.whole_seconds().max(0) as u64,
                        probe_kind: probe.probe_kind.clone(),
                        path_hash: probe.path_hash.clone(),
                        probe_error: probe.probe_error.clone(),
                        scan_truncated: probe.scan_truncated,
                        confidence: Confidence::Low,
                    },
                ),
                target_id: None,
            };
            let _ = ctx
                .event_tx
                .send(CommittableEvent {
                    event: ev,
                    new_hash: None,
                    path_for_db: PathBuf::new(),
                    target_id: String::new(),
                })
                .await;
            // Re-lock to set the latch. A concurrent record_hook_event() (from a
            // listener) between the clone above and here could have closed the
            // episode; re-opening it costs at most one extra tick of silence
            // before the next evaluate sees the fresh hook and re-arms. Benign.
            if let Some(r) = ctx.map.lock().get_mut(&key) {
                r.episode_open = true;
                r.last_emitted_at = Some(now);
            }
        }
    }
}

/// Production wiring inputs.
pub struct RunCfg {
    pub host_id: String,
    pub map: ActivityMap,
    pub enabled: Vec<AiTool>,
    pub window: Duration,
    pub horizon: Duration,
    pub tick: StdDuration,
    pub cap: ProbeCapRt,
    pub home: PathBuf,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    pub shutdown: CancellationToken,
}

pub async fn run(rc: RunCfg) {
    if rc.enabled.is_empty() {
        return; // feature OFF → no-op
    }
    let cap = rc.cap;
    let home = rc.home.clone();
    let ctx = SilenceTaskCtx {
        host_id: rc.host_id,
        map: rc.map,
        enabled: rc.enabled,
        window: rc.window,
        horizon: rc.horizon,
        event_tx: rc.event_tx,
        now_fn: Box::new(OffsetDateTime::now_utc),
        probe_fn: Box::new(move |agent, _uid| {
            let dirs = crate::hook_silence::session_dirs(agent, &home);
            crate::hook_silence::probe_dirs(crate::hook_silence::probe_kind_for(agent), &dirs, &cap)
        }),
    };
    let mut interval = tokio::time::interval(rc.tick);
    interval.tick().await; // skip immediate
    loop {
        tokio::select! {
            biased;
            _ = rc.shutdown.cancelled() => break,
            _ = interval.tick() => evaluate(&ctx).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_silence::{new_map, ActivityRecord, ProbeResult};
    use sigil_core::event::{AiTool, Evidence};
    use time::{Duration, OffsetDateTime};

    fn probe(active: bool, last: Option<OffsetDateTime>) -> ProbeResult {
        ProbeResult {
            active,
            last_activity_at: last,
            probe_kind: "codex_sessions".into(),
            path_hash: Some("blake3:x".into()),
            probe_error: None,
            scan_truncated: false,
        }
    }

    fn ctx_with(
        active: bool,
    ) -> (
        SilenceTaskCtx,
        tokio::sync::mpsc::Receiver<crate::state_task::CommittableEvent>,
    ) {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let map = new_map();
        map.lock().insert(
            (AiTool::Codex, 501),
            ActivityRecord {
                last_hook_event_at: now - Duration::hours(13),
                last_emitted_at: None,
                episode_open: false,
            },
        );
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let ctx = SilenceTaskCtx {
            host_id: "h".into(),
            map,
            enabled: vec![AiTool::Codex],
            window: Duration::hours(12),
            horizon: Duration::days(7),
            event_tx: tx,
            now_fn: Box::new(move || now),
            probe_fn: Box::new(move |_a, _u| probe(active, Some(now - Duration::minutes(5)))),
        };
        (ctx, rx)
    }

    #[tokio::test]
    async fn active_silent_emits_once_per_episode() {
        let (ctx, mut rx) = ctx_with(true);
        evaluate(&ctx).await;
        evaluate(&ctx).await; // same episode, second tick
        let ev = rx.recv().await.unwrap();
        assert!(matches!(
            ev.event.evidence,
            Evidence::PossibleHookActivitySilent(_)
        ));
        assert!(rx.try_recv().is_err()); // exactly one
    }

    #[tokio::test]
    async fn disabled_agent_never_emits() {
        let (mut ctx, mut rx) = ctx_with(true);
        ctx.enabled = vec![]; // opt-in empty
        evaluate(&ctx).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn inactive_session_does_not_emit() {
        let (ctx, mut rx) = ctx_with(false); // probe inactive
        evaluate(&ctx).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn resumed_hook_rearms_episode() {
        let (ctx, mut rx) = ctx_with(true);
        evaluate(&ctx).await;
        let _ = rx.recv().await.unwrap();
        // resumed hook traffic closes the episode + refreshes last seen…
        crate::hook_silence::record_hook_event(&ctx.map, AiTool::Codex, 501, (ctx.now_fn)());
        // …then age it back beyond W so it's silent again
        ctx.map
            .lock()
            .get_mut(&(AiTool::Codex, 501))
            .unwrap()
            .last_hook_event_at = (ctx.now_fn)() - Duration::hours(13);
        evaluate(&ctx).await;
        assert!(matches!(
            rx.recv().await.unwrap().event.evidence,
            Evidence::PossibleHookActivitySilent(_)
        ));
    }

    #[tokio::test]
    async fn disabled_policy_makes_run_return_immediately() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let rc = RunCfg {
            host_id: "h".into(),
            map: crate::hook_silence::new_map(),
            enabled: vec![],
            window: time::Duration::hours(12),
            horizon: time::Duration::days(7),
            tick: std::time::Duration::from_millis(5),
            cap: crate::hook_silence::ProbeCapRt {
                max_entries: 16,
                max_depth: 1,
                budget: std::time::Duration::from_millis(5),
            },
            home: std::env::temp_dir(),
            event_tx: tx,
            shutdown: tokio_util::sync::CancellationToken::new(),
        };
        tokio::time::timeout(std::time::Duration::from_millis(200), run(rc))
            .await
            .expect("run() must return immediately when enabled is empty");
    }

    #[tokio::test]
    async fn empty_map_no_alarm() {
        // restart behavior
        let (mut ctx, mut rx) = ctx_with(true);
        ctx.map = new_map();
        evaluate(&ctx).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn decayed_agent_in_map_does_not_emit() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(100);
        let map = new_map();
        // last hook 8 days ago > horizon (7d) → not expected, even though session is active
        map.lock().insert(
            (AiTool::Codex, 501),
            ActivityRecord {
                last_hook_event_at: now - Duration::days(8),
                last_emitted_at: None,
                episode_open: false,
            },
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let ctx = SilenceTaskCtx {
            host_id: "h".into(),
            map,
            enabled: vec![AiTool::Codex],
            window: Duration::hours(12),
            horizon: Duration::days(7),
            event_tx: tx,
            now_fn: Box::new(move || now),
            probe_fn: Box::new(move |_a, _u| probe(true, Some(now - Duration::minutes(5)))),
        };
        evaluate(&ctx).await;
        assert!(rx.try_recv().is_err());
    }
}
