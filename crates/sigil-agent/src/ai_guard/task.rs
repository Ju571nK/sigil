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

/// Shared state map keyed by `(tool, scope, pack_id)`. Persists between calls
/// so `eval_and_maybe_emit` can deduplicate identical reason sets across
/// triggers. The `pack_id` dimension ensures two parsers sharing the same
/// (tool, scope) but belonging to different rule packs never collide.
/// Read by the operator IPC handler (Task 7) for `sigil show risk`.
pub type StateMap = HashMap<(AiTool, AiGuardScope, Option<String>), CachedAssessment>;

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
    /// #147 — the dangerous-toggle kinds present at this assessment. Compared
    /// against the next assessment's set to detect OFF→ON transitions (drift).
    pub dangerous_toggles: std::collections::BTreeSet<String>,
}

/// Bundle of shared dependencies the task needs at construction. Built once
/// in `runtime::run` and consumed by `ai_guard::task::run`.
pub struct TaskCtx {
    /// Storage is `Arc<dyn ..>` (not `Box<dyn ..>`) so the dispatcher can
    /// snapshot-clone the vec before dropping the read guard and entering
    /// an await — parking_lot RwLockReadGuard isn't Send across `.await`.
    /// Phase 3b.6.1 — policy_reload mutates this list to add/remove
    /// `ContinueDevProjectParser` instances as `continue_workspaces` changes.
    pub parsers: Arc<RwLock<Vec<Arc<dyn AiGuardParser>>>>,
    pub fc_rx: broadcast::Receiver<PathBuf>,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    pub state: Arc<RwLock<StateMap>>,
    pub heartbeat_interval: Duration,
    pub home_dir: PathBuf,
    pub host_id: String,
    /// Phase 3b.3 — shared registry of external hook-script paths per parser
    /// (tool, scope). Populated by runtime/reload; read by the dispatch loop
    /// to route fsnotify events on script paths.
    pub ext_scripts: crate::ai_guard::ExtScriptRegistry,
    /// Phase 3b.5 — shared rubric (operator-tunable weights). Snapshot-
    /// cloned on each assess cycle before any await; rebuilt + swapped
    /// by policy_reload_task on envelope changes.
    pub rubric: crate::ai_guard::RubricHandle,
}

/// Main task loop. Boots, then selects between file-change broadcasts and
/// the heartbeat tick until the broadcast sender is dropped (shutdown).
pub async fn run(mut ctx: TaskCtx) {
    // 1. Initial scan on boot. Snapshot-clone the parsers vec before any
    //    `.await` so the parking_lot RwLockReadGuard is dropped — guards are
    //    NOT Send across an await. Cloning a `Vec<Arc<dyn>>` just bumps each
    //    Arc refcount, so this is cheap.
    {
        let snapshot: Vec<Arc<dyn AiGuardParser>> = ctx.parsers.read().clone();
        for parser in &snapshot {
            eval_and_maybe_emit(parser.as_ref(), &ctx, true).await;
        }
    }

    let mut heartbeat = tokio::time::interval(ctx.heartbeat_interval);
    heartbeat.tick().await; // skip the immediate first tick.

    loop {
        tokio::select! {
            recv = ctx.fc_rx.recv() => {
                match recv {
                    Ok(path) => {
                        // Snapshot per cycle so reload mutations between cycles take effect.
                        // Clone the ext-script HashMap once so the parking_lot read guard is
                        // dropped before any `.await` — guards are NOT Send across await.
                        let snapshot: Vec<Arc<dyn AiGuardParser>> = ctx.parsers.read().clone();
                        let ext_map = ctx.ext_scripts.read().clone();
                        for parser in &snapshot {
                            let in_watched = parser
                                .watched_paths(&ctx.home_dir)
                                .iter()
                                .any(|p| path_matches(&path, p));
                            let in_ext_script = ext_map
                                .get(&(parser.tool(), parser.scope()))
                                .map(|v| v.iter().any(|p| path_matches(&path, p)))
                                .unwrap_or(false);
                            if in_watched || in_ext_script {
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
                let snapshot: Vec<Arc<dyn AiGuardParser>> = ctx.parsers.read().clone();
                for parser in &snapshot {
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
    // Phase 3b.5 — snapshot-clone the Rubric BEFORE any subsequent await.
    // Cheap: weights is a small HashMap.
    let rubric_snapshot = ctx.rubric.read().clone();
    let score = rubric_snapshot.score(&reasons);
    let bucket = rubric::bucket(score);
    let reasons_hash = rubric::canonical_hash(&reasons);
    let key = (
        parser.tool(),
        parser.scope(),
        parser.rule_pack_id().map(|s| s.to_string()),
    );
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

    // #147 — dangerous-toggle drift. A toggle is "dangerous" iff its reason
    // kind is in DANGEROUS_TOGGLE_KINDS. We compare the current set against the
    // previous cached set and emit a one-time event for each toggle that
    // appeared (OFF→ON). The standing state still rides the normal
    // AiGuardRiskAssessed reasons; this is an ADDITIONAL change event.
    //
    // MVP limitations (codex-review, all P2, none a current bug):
    //  1. Baseline is keyed by the full StateMap key (tool, scope, rule_pack_id),
    //     so a toggle first seen under a *renamed* rule pack id is baselined (no
    //     drift) — consistent with how every assessment is keyed. Built-in
    //     toggles (rule_pack_id = None) are unaffected.
    //  2. The prev-read / new-write below are not one atomic critical section.
    //     Safe today because the eval loop is serialized per key; if parser eval
    //     ever runs concurrently for the same key, fold read+compare+write into a
    //     single `state.write()` to avoid a double-fire.
    //  3. The cache advances before the drift send, so a send that fails during
    //     shutdown drops that one alert (at-most-once). The standing reason still
    //     re-establishes posture, so nothing about *state* is lost.
    let new_toggles: std::collections::BTreeSet<String> = rubric::dangerous_toggles(&reasons)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    // Only fire when there is a PREVIOUS cached assessment for this key. The
    // first/boot assessment merely establishes the baseline, so a daemon
    // restart with a toggle already on never false-fires.
    let appeared: Vec<String> = match prev.as_ref() {
        Some(p) => new_toggles
            .difference(&p.dangerous_toggles)
            .cloned()
            .collect(),
        None => Vec::new(),
    };

    ctx.state.write().insert(
        key.clone(),
        CachedAssessment {
            score,
            bucket,
            reasons_blake3: reasons_hash,
            reasons_count: reasons.len(),
            last_assessed_ts: now,
            dangerous_toggles: new_toggles,
        },
    );

    // Emit one drift event per appeared toggle, via the same sink/channel and
    // full-Event envelope as AiGuardRiskAssessed below.
    for toggle in appeared {
        let drift_event = Event {
            schema_version: SCHEMA_VERSION,
            event_id: uuid::Uuid::now_v7(),
            ts: now,
            host_id: ctx.host_id.clone(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::AiGuardToggleDrift {
                tool: key.0,
                scope: key.1.clone(),
                toggle,
                rule_pack_id: key.2.clone(),
                tool_label: parser.tool_label().map(|s| s.to_string()),
            },
            target_id: None,
        };
        if ctx
            .event_tx
            .send(CommittableEvent {
                event: drift_event,
                new_hash: None,
                path_for_db: PathBuf::new(),
                target_id: String::new(),
            })
            .await
            .is_err()
        {
            tracing::debug!(tool = ?key.0, "ai_guard drift event_tx send failed (sink closed during shutdown?)");
        }
    }

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
            scope: key.1.clone(),
            score,
            bucket,
            reasons,
            is_reattestation,
            rule_pack_id: key.2.clone(),
            tool_label: parser.tool_label().map(|s| s.to_string()),
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
        scope: AiGuardScope,
        pack_id: Option<String>,
        tool_label: Option<String>,
        scripts: StdMutex<Vec<Vec<AiGuardReason>>>,
        watched: Vec<PathBuf>,
    }

    impl AiGuardParser for ScriptedParser {
        fn tool(&self) -> AiTool {
            self.tool
        }
        fn scope(&self) -> AiGuardScope {
            self.scope.clone()
        }
        fn rule_pack_id(&self) -> Option<&str> {
            self.pack_id.as_deref()
        }
        fn tool_label(&self) -> Option<&str> {
            self.tool_label.as_deref()
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
                parsers: Arc::new(RwLock::new(
                    vec![Arc::new(parser) as Arc<dyn AiGuardParser>],
                )),
                fc_rx,
                event_tx: tx,
                state: Arc::new(RwLock::new(HashMap::new())),
                heartbeat_interval: hb,
                home_dir: PathBuf::from("/tmp/test-home"),
                host_id: "test-host".into(),
                ext_scripts: crate::ai_guard::empty_ext_script_registry(),
                rubric: crate::ai_guard::default_rubric_handle(),
            },
            rx,
        )
    }

    /// Receive the next `AiGuardRiskAssessed` event, skipping any
    /// `AiGuardToggleDrift` events emitted earlier in the same cycle (#147).
    async fn recv_next_risk_assessed(
        events: &mut mpsc::Receiver<CommittableEvent>,
    ) -> CommittableEvent {
        loop {
            let ev = events.recv().await.expect("event");
            if matches!(ev.event.evidence, Evidence::AiGuardToggleDrift { .. }) {
                continue;
            }
            return ev;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn boot_emits_initial_event_even_when_clean() {
        let (_tx, fc_rx) = broadcast::channel(8);
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
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
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
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
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
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
        // SandboxDisabled is also a dangerous toggle, so an OFF→ON drift event
        // precedes the risk event this cycle. Skip past it to the risk event.
        let ev = recv_next_risk_assessed(&mut events).await;
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
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
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
            fn scope(&self) -> AiGuardScope {
                AiGuardScope::UserGlobal
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
            parsers: Arc::new(RwLock::new(vec![
                Arc::new(ErrorParser) as Arc<dyn AiGuardParser>
            ])),
            fc_rx,
            event_tx,
            state: Arc::new(RwLock::new(HashMap::new())),
            heartbeat_interval: Duration::from_secs(24 * 3600),
            home_dir: PathBuf::from("/tmp"),
            host_id: "h".into(),
            ext_scripts: crate::ai_guard::empty_ext_script_registry(),
            rubric: crate::ai_guard::default_rubric_handle(),
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
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
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
        // SandboxDisabled (the changed reason) is also a dangerous toggle, so a
        // drift event precedes the risk event this cycle. Skip to the risk one.
        let ev = recv_next_risk_assessed(&mut events).await;
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

    #[tokio::test]
    async fn emit_carries_tool_label_from_parser() {
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (event_tx, mut events) = mpsc::channel(16);
        let state: Arc<RwLock<StateMap>> = Arc::new(RwLock::new(HashMap::new()));
        let ctx = TaskCtx {
            parsers: Arc::new(RwLock::new(vec![])),
            fc_rx,
            event_tx,
            state: state.clone(),
            heartbeat_interval: Duration::from_secs(24 * 3600),
            home_dir: PathBuf::from("/tmp/test-home"),
            host_id: "test-host".into(),
            ext_scripts: crate::ai_guard::empty_ext_script_registry(),
            rubric: crate::ai_guard::default_rubric_handle(),
        };
        let parser = ScriptedParser {
            tool: AiTool::Other,
            scope: AiGuardScope::UserGlobal,
            pack_id: Some("p".to_string()),
            tool_label: Some("acme-ai".to_string()),
            scripts: StdMutex::new(vec![vec![AiGuardReason::SandboxDisabled]]),
            watched: vec![],
        };
        eval_and_maybe_emit(&parser, &ctx, true).await;
        let ev = events.recv().await.expect("tool_label event");
        let j = serde_json::to_value(&ev.event).unwrap();
        assert_eq!(j["evidence"]["tool"], "other");
        assert_eq!(j["evidence"]["tool_label"], "acme-ai");
    }

    #[tokio::test]
    async fn distinct_pack_ids_do_not_collide_in_state() {
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (event_tx, _events) = mpsc::channel(16);
        let state: Arc<RwLock<StateMap>> = Arc::new(RwLock::new(HashMap::new()));
        let ctx = TaskCtx {
            parsers: Arc::new(RwLock::new(vec![])),
            fc_rx,
            event_tx,
            state: state.clone(),
            heartbeat_interval: Duration::from_secs(24 * 3600),
            home_dir: PathBuf::from("/tmp/test-home"),
            host_id: "test-host".into(),
            ext_scripts: crate::ai_guard::empty_ext_script_registry(),
            rubric: crate::ai_guard::default_rubric_handle(),
        };
        // Parser A: tool=Gemini, scope=Project{path:"/r"}, pack_id=Some("pack-a"),
        //   scripts=[vec![AiGuardReason::SandboxDisabled]]
        let a = ScriptedParser {
            tool: AiTool::Gemini,
            scope: AiGuardScope::Project { path: "/r".into() },
            pack_id: Some("pack-a".to_string()),
            tool_label: None,
            scripts: StdMutex::new(vec![vec![AiGuardReason::SandboxDisabled]]),
            watched: vec![],
        };
        // Parser B: tool=Gemini, scope=Project{path:"/r"}, pack_id=Some("pack-b"),
        //   scripts=[vec![]]  (clean)
        let b = ScriptedParser {
            tool: AiTool::Gemini,
            scope: AiGuardScope::Project { path: "/r".into() },
            pack_id: Some("pack-b".to_string()),
            tool_label: None,
            scripts: StdMutex::new(vec![vec![]]),
            watched: vec![],
        };
        eval_and_maybe_emit(&a, &ctx, true).await;
        eval_and_maybe_emit(&b, &ctx, true).await;
        let scope = AiGuardScope::Project { path: "/r".into() };
        let s = ctx.state.read();
        assert!(s.contains_key(&(AiTool::Gemini, scope.clone(), Some("pack-a".to_string()))));
        assert!(s.contains_key(&(AiTool::Gemini, scope.clone(), Some("pack-b".to_string()))));
        assert_eq!(s.len(), 2);
    }

    // ---- #147 dangerous-toggle drift -------------------------------------

    /// Build a parsers-less ctx + a shared event channel for driving a single
    /// parser through `eval_and_maybe_emit` directly (mirrors
    /// `emit_carries_tool_label_from_parser`). Returns (ctx, event receiver).
    fn drift_ctx() -> (TaskCtx, mpsc::Receiver<CommittableEvent>) {
        let (_fc_tx, fc_rx) = broadcast::channel(8);
        let (event_tx, events) = mpsc::channel(32);
        let ctx = TaskCtx {
            parsers: Arc::new(RwLock::new(vec![])),
            fc_rx,
            event_tx,
            state: Arc::new(RwLock::new(HashMap::new())),
            heartbeat_interval: Duration::from_secs(24 * 3600),
            home_dir: PathBuf::from("/tmp/test-home"),
            host_id: "test-host".into(),
            ext_scripts: crate::ai_guard::empty_ext_script_registry(),
            rubric: crate::ai_guard::default_rubric_handle(),
        };
        (ctx, events)
    }

    /// Drain the channel and return only the `AiGuardToggleDrift` toggles, in
    /// emission order. (Each `eval_and_maybe_emit` also emits an
    /// `AiGuardRiskAssessed`; we ignore those here.)
    fn drain_drift_toggles(events: &mut mpsc::Receiver<CommittableEvent>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(ce) = events.try_recv() {
            if let Evidence::AiGuardToggleDrift { toggle, .. } = ce.event.evidence {
                out.push(toggle);
            }
        }
        out
    }

    fn one_shot_parser(reasons: Vec<AiGuardReason>) -> ScriptedParser {
        ScriptedParser {
            tool: AiTool::Gemini,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![reasons]),
            watched: vec![],
        }
    }

    /// Baseline: first assessment with a dangerous toggle already present must
    /// NOT fire a drift event — boot establishes the baseline.
    #[tokio::test]
    async fn drift_baseline_does_not_fire() {
        let (ctx, mut events) = drift_ctx();
        let p = one_shot_parser(vec![AiGuardReason::AutoApprovalEnabled {
            mode: "auto_edit".into(),
        }]);
        eval_and_maybe_emit(&p, &ctx, true).await;
        assert!(
            drain_drift_toggles(&mut events).is_empty(),
            "boot assessment must not fire drift"
        );
        // Baseline was recorded.
        let key = (AiTool::Gemini, AiGuardScope::UserGlobal, None);
        assert!(ctx.state.read()[&key]
            .dangerous_toggles
            .contains("auto_approval_enabled"));
    }

    /// off→on: assess with toggle off, then flip it on → EXACTLY ONE drift
    /// event for that toggle kind.
    #[tokio::test]
    async fn drift_off_to_on_fires_once() {
        let (ctx, mut events) = drift_ctx();
        // First (baseline): toggle off — a non-dangerous reason so the reason
        // set is non-empty but carries no dangerous toggle.
        let off = one_shot_parser(vec![AiGuardReason::PermissionsDenyEmpty]);
        eval_and_maybe_emit(&off, &ctx, true).await;
        assert!(drain_drift_toggles(&mut events).is_empty());

        // Second: toggle on.
        let on = one_shot_parser(vec![AiGuardReason::SandboxDisabled]);
        eval_and_maybe_emit(&on, &ctx, false).await;
        assert_eq!(
            drain_drift_toggles(&mut events),
            vec!["sandbox_disabled".to_string()]
        );
    }

    /// already-on: toggle on across two assessments → no drift on the second.
    #[tokio::test]
    async fn drift_already_on_does_not_refire() {
        let (ctx, mut events) = drift_ctx();
        let on1 = one_shot_parser(vec![AiGuardReason::SandboxDisabled]);
        eval_and_maybe_emit(&on1, &ctx, true).await; // baseline (no drift)
        assert!(drain_drift_toggles(&mut events).is_empty());

        // Same toggle present again — force_emit so an AiGuardRiskAssessed is
        // produced, but the toggle was already in prev → no drift.
        let on2 = one_shot_parser(vec![AiGuardReason::SandboxDisabled]);
        eval_and_maybe_emit(&on2, &ctx, true).await;
        assert!(
            drain_drift_toggles(&mut events).is_empty(),
            "an already-on toggle must not re-fire"
        );
    }

    /// on→off: toggle removed → no drift (de-escalation is silent).
    #[tokio::test]
    async fn drift_on_to_off_does_not_fire() {
        let (ctx, mut events) = drift_ctx();
        let on = one_shot_parser(vec![AiGuardReason::SandboxDisabled]);
        eval_and_maybe_emit(&on, &ctx, true).await; // baseline
        let _ = drain_drift_toggles(&mut events);

        let off = one_shot_parser(vec![AiGuardReason::PermissionsDenyEmpty]);
        eval_and_maybe_emit(&off, &ctx, false).await;
        assert!(
            drain_drift_toggles(&mut events).is_empty(),
            "on→off must not fire drift"
        );
        // Cache reflects the toggle is gone.
        let key = (AiTool::Gemini, AiGuardScope::UserGlobal, None);
        assert!(ctx.state.read()[&key].dangerous_toggles.is_empty());
    }

    /// on→off→on: the toggle re-appearing fires drift again (each on-transition).
    #[tokio::test]
    async fn drift_on_off_on_fires_again() {
        let (ctx, mut events) = drift_ctx();
        eval_and_maybe_emit(
            &one_shot_parser(vec![AiGuardReason::SandboxDisabled]),
            &ctx,
            true,
        )
        .await; // baseline on
        let _ = drain_drift_toggles(&mut events);
        eval_and_maybe_emit(
            &one_shot_parser(vec![AiGuardReason::PermissionsDenyEmpty]),
            &ctx,
            false,
        )
        .await; // off
        let _ = drain_drift_toggles(&mut events);
        eval_and_maybe_emit(
            &one_shot_parser(vec![AiGuardReason::SandboxDisabled]),
            &ctx,
            false,
        )
        .await; // on again
        assert_eq!(
            drain_drift_toggles(&mut events),
            vec!["sandbox_disabled".to_string()]
        );
    }

    /// Multiple toggles appearing at once → one drift event per appeared toggle.
    #[tokio::test]
    async fn drift_multiple_toggles_one_event_each() {
        let (ctx, mut events) = drift_ctx();
        // Baseline: none.
        eval_and_maybe_emit(
            &one_shot_parser(vec![AiGuardReason::PermissionsDenyEmpty]),
            &ctx,
            true,
        )
        .await;
        let _ = drain_drift_toggles(&mut events);

        // Two dangerous toggles appear at once.
        let both = one_shot_parser(vec![
            AiGuardReason::SandboxDisabled,
            AiGuardReason::AutoApprovalEnabled {
                mode: "auto_edit".into(),
            },
        ]);
        eval_and_maybe_emit(&both, &ctx, false).await;
        let mut got = drain_drift_toggles(&mut events);
        got.sort();
        assert_eq!(
            got,
            vec![
                "auto_approval_enabled".to_string(),
                "sandbox_disabled".to_string()
            ]
        );
    }

    /// Full-loop off→on via the file-change trigger: drift event flows through
    /// `run()` exactly like the AiGuardRiskAssessed sibling.
    #[tokio::test(start_paused = true)]
    async fn drift_off_to_on_through_run_loop() {
        let (tx, fc_rx) = broadcast::channel(8);
        let watched = PathBuf::from("/tmp/test-home/.claude/settings.json");
        let parser = ScriptedParser {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            pack_id: None,
            tool_label: None,
            scripts: StdMutex::new(vec![
                vec![AiGuardReason::PermissionsDenyEmpty], // boot: toggle off
                vec![AiGuardReason::SandboxDisabled],      // change: toggle on
            ]),
            watched: vec![watched.clone()],
        };
        let (ctx, mut events) = ctx_with(parser, fc_rx, Duration::from_secs(24 * 3600));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        // Boot: AiGuardRiskAssessed only, no drift.
        let boot = events.recv().await.expect("boot");
        assert!(matches!(
            boot.event.evidence,
            Evidence::AiGuardRiskAssessed { .. }
        ));

        tx.send(watched).unwrap();
        tokio::time::advance(Duration::from_millis(50)).await;

        // The change cycle emits a drift event AND an AiGuardRiskAssessed.
        // Collect both (order: drift is sent before the risk event).
        let mut saw_drift = None;
        let mut saw_risk = false;
        for _ in 0..2 {
            let ev = tokio::time::timeout(Duration::from_millis(100), events.recv())
                .await
                .expect("event available")
                .expect("event");
            match ev.event.evidence {
                Evidence::AiGuardToggleDrift { toggle, .. } => saw_drift = Some(toggle),
                Evidence::AiGuardRiskAssessed { .. } => saw_risk = true,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(saw_drift.as_deref(), Some("sandbox_disabled"));
        assert!(saw_risk, "drift is IN ADDITION to AiGuardRiskAssessed");
        h.abort();
    }
}
