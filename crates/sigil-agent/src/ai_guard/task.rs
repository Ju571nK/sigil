//! Phase 3b.1 — ai_guard_task orchestration.
//!
//! Trigger model:
//! - **Boot**: every parser runs once, force-emit even if score is 0.
//! - **File change**: hasher broadcasts each canonical path it just hashed;
//!   matching parser re-evaluates and emits only if `canonical_hash(reasons)`
//!   changed. NOTE: the hasher only emits paths it processed, which means
//!   only paths covered by an active policy target. The baseline OSS policy
//!   (sigil-rules-basic) includes `~/.claude/` and `~/.codex/`, so this
//!   trigger works out-of-box. If an operator removes those targets from
//!   their custom policy, this task falls back to heartbeat-only.
//! - **Heartbeat** (24h): every parser re-evaluates and force-emits. Provides
//!   liveness regardless of whether file-change events flow.

use crate::ai_guard::parser::AiGuardParser;
use crate::ai_guard::rubric;
use crate::state_task::CommittableEvent;
use parking_lot::RwLock;
use sigil_core::event::{
    AiGuardBucket, AiGuardScope, AiTool, Event, Evidence, Severity, SourceKind, Subject,
    AGENT_VERSION, SCHEMA_VERSION,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{broadcast, mpsc};

/// Shared state map keyed by `(tool, scope)`. Persists between calls so
/// `eval_and_maybe_emit` can deduplicate identical reason sets across
/// triggers. Read by the operator IPC handler (Task 7) for `sigil show risk`.
pub type StateMap = HashMap<(AiTool, AiGuardScope), CachedAssessment>;

/// One parser's last emitted state, kept in `StateMap` for change-detection
/// and IPC introspection. The `reasons_blake3` field is what
/// `eval_and_maybe_emit` compares against to decide whether to emit.
#[derive(Clone, Debug)]
pub struct CachedAssessment {
    pub score: f32,
    pub bucket: AiGuardBucket,
    pub reasons_blake3: [u8; 32],
    pub reasons_count: usize,
    pub last_assessed_ts: OffsetDateTime,
}

/// Bundle of shared dependencies the task needs at construction. Built once
/// in `runtime::run` and consumed by `ai_guard::task::run`.
pub struct TaskCtx {
    pub parsers: Vec<Box<dyn AiGuardParser>>,
    pub fc_rx: broadcast::Receiver<PathBuf>,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    pub state: Arc<RwLock<StateMap>>,
    pub heartbeat_interval: Duration,
    pub home_dir: PathBuf,
    pub host_id: String,
}

/// Main task loop. Boots, then selects between file-change broadcasts and
/// the heartbeat tick until the broadcast sender is dropped (shutdown).
pub async fn run(mut ctx: TaskCtx) {
    // 1. Initial scan on boot.
    for parser in &ctx.parsers {
        eval_and_maybe_emit(parser.as_ref(), &ctx, true).await;
    }

    let mut heartbeat = tokio::time::interval(ctx.heartbeat_interval);
    heartbeat.tick().await; // skip the immediate first tick.

    loop {
        tokio::select! {
            recv = ctx.fc_rx.recv() => {
                match recv {
                    Ok(path) => {
                        for parser in &ctx.parsers {
                            if parser
                                .watched_paths(&ctx.home_dir)
                                .iter()
                                .any(|p| path_matches(&path, p))
                            {
                                eval_and_maybe_emit(parser.as_ref(), &ctx, false).await;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "ai_guard fc_rx lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Sender dropped — runtime shutting down.
                        return;
                    }
                }
            }
            _ = heartbeat.tick() => {
                for parser in &ctx.parsers {
                    eval_and_maybe_emit(parser.as_ref(), &ctx, true).await;
                }
            }
        }
    }
}

/// Match an incoming change path against a watched path/dir. A watched dir
/// matches any path inside it; a watched file matches by exact equality.
///
/// Assumes both `incoming` and `watched` are already canonical. Incoming
/// paths come from the hasher, which receives them post-`dunce::canonicalize`
/// from the normalizer. Watched paths come from each parser's
/// `watched_paths(home_dir)`, which uses raw `home_dir.join(...)` — no
/// explicit canonicalization. On standard macOS / Linux the user's HOME is
/// canonical, so this assumption holds. If a future deployment uses a
/// symlinked HOME (rare), file-change triggers may fail to match silently
/// and the 24h heartbeat will still keep the assessment live.
fn path_matches(incoming: &std::path::Path, watched: &std::path::Path) -> bool {
    if incoming == watched {
        return true;
    }
    incoming.starts_with(watched)
}

async fn eval_and_maybe_emit(parser: &dyn AiGuardParser, ctx: &TaskCtx, force_emit: bool) {
    let reasons = match parser.assess(&ctx.home_dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = ?e, tool = ?parser.tool(), "ai_guard assess failed; skip cycle");
            return;
        }
    };
    let score = rubric::score(&reasons);
    let bucket = rubric::bucket(score);
    let reasons_hash = rubric::canonical_hash(&reasons);
    let key = (parser.tool(), AiGuardScope::UserGlobal);
    let prev = ctx.state.read().get(&key).cloned();
    let changed = prev
        .as_ref()
        .map(|p| p.reasons_blake3 != reasons_hash)
        .unwrap_or(true);
    if !changed && !force_emit {
        return;
    }
    let now = OffsetDateTime::now_utc();
    // Reattestation iff this emit is force-driven AND the reason set is
    // unchanged from the previous one. Boot (no prior state) is NOT a
    // reattestation even though it's force-emitted.
    let is_reattestation = force_emit && prev.is_some() && !changed;
    ctx.state.write().insert(
        key.clone(),
        CachedAssessment {
            score,
            bucket,
            reasons_blake3: reasons_hash,
            reasons_count: reasons.len(),
            last_assessed_ts: now,
        },
    );
    let event = Event {
        schema_version: SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: now,
        host_id: ctx.host_id.clone(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Warn,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence: Evidence::AiGuardRiskAssessed {
            tool: key.0,
            scope: key.1,
            score,
            bucket,
            reasons,
            is_reattestation,
        },
        target_id: None,
    };
    if ctx
        .event_tx
        .send(CommittableEvent {
            event,
            new_hash: None,
            path_for_db: PathBuf::new(),
            target_id: String::new(),
        })
        .await
        .is_err()
    {
        tracing::debug!(tool = ?key.0, "ai_guard event_tx send failed (sink closed during shutdown?)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_guard::parser::AssessError;
    use sigil_core::event::AiGuardReason;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::{broadcast, mpsc};

    /// Test parser whose `assess()` returns scripted reason sets in order.
    struct ScriptedParser {
        tool: AiTool,
        scripts: StdMutex<Vec<Vec<AiGuardReason>>>,
        watched: Vec<PathBuf>,
    }

    impl AiGuardParser for ScriptedParser {
        fn tool(&self) -> AiTool {
            self.tool
        }
        fn watched_paths(&self, _home: &std::path::Path) -> Vec<PathBuf> {
            self.watched.clone()
        }
        fn assess(&self, _home: &std::path::Path) -> Result<Vec<AiGuardReason>, AssessError> {
            let mut s = self.scripts.lock().unwrap();
            if s.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(s.remove(0))
            }
        }
    }

    fn ctx_with(
        parser: ScriptedParser,
        fc_rx: broadcast::Receiver<PathBuf>,
        hb: Duration,
    ) -> (TaskCtx, mpsc::Receiver<CommittableEvent>) {
        let (tx, rx) = mpsc::channel(16);
        (
            TaskCtx {
                parsers: vec![Box::new(parser)],
                fc_rx,
                event_tx: tx,
                state: Arc::new(RwLock::new(HashMap::new())),
                heartbeat_interval: hb,
                home_dir: PathBuf::from("/tmp/test-home"),
                host_id: "test-host".into(),
            },
            rx,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn boot_emits_initial_event_even_when_clean() {
        let (_tx, fc_rx) = broadcast::channel(8);
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scripts: StdMutex::new(vec![vec![]]),
            watched: vec![PathBuf::from("/tmp/test-home/.claude/settings.json")],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_secs(24 * 3600));
        let h = tokio::spawn(run(ctx));
        // Allow the boot scan to fire.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let ev = events.recv().await.expect("boot event");
        match ev.event.evidence {
            Evidence::AiGuardRiskAssessed {
                score,
                bucket,
                reasons,
                is_reattestation,
                ..
            } => {
                assert_eq!(score, 0.0);
                assert_eq!(bucket, AiGuardBucket::Low);
                assert!(reasons.is_empty());
                assert!(
                    !is_reattestation,
                    "boot scan with no prior state is not a re-attestation"
                );
            }
            other => panic!("expected AiGuardRiskAssessed, got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn unchanged_file_change_does_not_emit() {
        let (tx, fc_rx) = broadcast::channel(8);
        let watched = PathBuf::from("/tmp/test-home/.claude/settings.json");
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty], // boot
                vec![AiGuardReason::PermissionsDenyEmpty], // identical → no emit
            ]),
            watched: vec![watched.clone()],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_secs(24 * 3600));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot event");
        tx.send(watched).unwrap();
        tokio::time::advance(Duration::from_millis(50)).await;
        // Should NOT receive a second event.
        let attempt = tokio::time::timeout(Duration::from_millis(100), events.recv()).await;
        assert!(attempt.is_err(), "expected no second emit, got {attempt:?}");
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn changed_file_change_emits_with_is_reattestation_false() {
        let (tx, fc_rx) = broadcast::channel(8);
        let watched = PathBuf::from("/tmp/test-home/.claude/settings.json");
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty],
                vec![AiGuardReason::SandboxDisabled],
            ]),
            watched: vec![watched.clone()],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_secs(24 * 3600));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot");
        tx.send(watched).unwrap();
        tokio::time::advance(Duration::from_millis(50)).await;
        let ev = events.recv().await.expect("change event");
        match ev.event.evidence {
            Evidence::AiGuardRiskAssessed {
                is_reattestation, ..
            } => assert!(!is_reattestation),
            other => panic!("got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_force_emits_with_is_reattestation_true_when_unchanged() {
        let (_tx, fc_rx) = broadcast::channel(8);
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty],
                vec![AiGuardReason::PermissionsDenyEmpty], // heartbeat — same
            ]),
            watched: vec![PathBuf::from("/tmp/test-home/.claude/settings.json")],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_millis(100));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot");
        tokio::time::advance(Duration::from_millis(150)).await;
        let ev = events.recv().await.expect("heartbeat event");
        match ev.event.evidence {
            Evidence::AiGuardRiskAssessed {
                is_reattestation, ..
            } => assert!(
                is_reattestation,
                "heartbeat with unchanged reasons must be re-attestation"
            ),
            other => panic!("got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn parser_assess_error_is_logged_and_does_not_emit() {
        struct ErrorParser;
        impl AiGuardParser for ErrorParser {
            fn tool(&self) -> AiTool {
                AiTool::ClaudeCode
            }
            fn watched_paths(&self, _h: &std::path::Path) -> Vec<PathBuf> {
                vec![PathBuf::from("/tmp/x")]
            }
            fn assess(&self, _h: &std::path::Path) -> Result<Vec<AiGuardReason>, AssessError> {
                Err(AssessError::Parse {
                    path: PathBuf::from("/tmp/x"),
                    message: "mock".into(),
                })
            }
        }
        let (_tx, fc_rx) = broadcast::channel(8);
        let (event_tx, mut events) = mpsc::channel(8);
        let ctx = TaskCtx {
            parsers: vec![Box::new(ErrorParser)],
            fc_rx,
            event_tx,
            state: Arc::new(RwLock::new(HashMap::new())),
            heartbeat_interval: Duration::from_secs(24 * 3600),
            home_dir: PathBuf::from("/tmp"),
            host_id: "h".into(),
        };
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let attempt = tokio::time::timeout(Duration::from_millis(50), events.recv()).await;
        assert!(attempt.is_err(), "errored parser should not emit");
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_with_changed_reasons_emits_is_reattestation_false() {
        let (_tx, fc_rx) = broadcast::channel(8);
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty], // boot
                vec![AiGuardReason::SandboxDisabled],      // heartbeat — different
            ]),
            watched: vec![PathBuf::from("/tmp/test-home/.claude/settings.json")],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_millis(100));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot event");
        tokio::time::advance(Duration::from_millis(150)).await;
        let ev = events.recv().await.expect("heartbeat event");
        match ev.event.evidence {
            Evidence::AiGuardRiskAssessed {
                is_reattestation, ..
            } => assert!(
                !is_reattestation,
                "heartbeat with CHANGED reasons must NOT be reattestation"
            ),
            other => panic!("got {other:?}"),
        }
        h.abort();
    }
}
