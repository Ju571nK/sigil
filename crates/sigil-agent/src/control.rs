//! Control IPC: UDS on Unix, Named Pipe on Windows.
//!
//! Phase 1 supports a single command: `{"cmd":"stats"}` returning the current
//! Heartbeat-equivalent payload as JSON.

use parking_lot::RwLock;
use sigil_core::stats::Stats;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use crate::policy_apply::{apply, ApplyContext, ApplyOutcome};

// The control-socket wire protocol now lives in `sigil-core::control_proto`, so
// `sigil-mcp` (local-mode client) can share the contract without depending on
// this crate. Re-exported here so existing `crate::control::{...}` paths keep
// working.
pub use sigil_core::control_proto::{
    ApplyPolicyResult, DoctorAiGuardReport, ExtScriptSummary, ParserInfo, PerRepoSummary,
    PolicyStatusPayload, Request, Response, RiskPayload, RiskSummary, RubricEntry, RulePackInfo,
    TargetSummary, TargetsPayload,
};

/// Default control-socket path. As root, the system path `/var/run/sigil`
/// (matches the systemd unit's `RuntimeDirectory=`). A non-root agent (macOS,
/// non-root Linux — e.g. the 2-machine test) can't write there, so fall back
/// to `$XDG_RUNTIME_DIR/sigil` (else `$TMPDIR`/`/tmp/sigil-<uid>`), keeping the
/// control plane usable without elevation. Override with `--control-socket`.
/// `sigil run` binds it; `sigil show stats` and `sigil-sender` connect to it.
/// On Windows the named pipe is used instead and this value is ignored.
///
/// The pure branch logic lives in `sigil_core::control_proto::resolve_control_socket`;
/// this wrapper supplies the euid/root/XDG/TMPDIR inputs.
pub fn default_control_socket() -> PathBuf {
    sigil_core::control_proto::resolve_control_socket(
        is_root(),
        std::env::var("XDG_RUNTIME_DIR")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("TMPDIR").ok().filter(|s| !s.is_empty()),
        current_uid(),
    )
}

/// True when the process effective uid is 0 (root). Non-Unix: always false.
/// Also consulted by the keystore default in `runtime`.
#[cfg(unix)]
pub(crate) fn is_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(unix))]
pub(crate) fn is_root() -> bool {
    false
}

/// Process real uid — namespaces the fallback socket dir in shared `/tmp`.
/// Non-Unix: 0 (unused; Windows uses the named pipe).
#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}
#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Default control named-pipe name on Windows.
pub fn default_control_pipe_name() -> String {
    r"\\.\pipe\sigil-control".to_string()
}

/// Shared context bundle passed to both platform `serve` functions.
pub struct ControlContext {
    pub stats: Arc<Stats>,
    pub apply_ctx: Arc<ApplyContext>,
    /// Used by `PolicyStatus` to read the active envelope's `valid_until`.
    /// Set by the `policy_expiry_task` (Task A6.4) on each successful apply.
    pub active_valid_until: Arc<RwLock<Option<time::OffsetDateTime>>>,
    /// Live snapshot of the active compiled-target set. Read by the `Targets`
    /// handler. Updated by `policy_reload_task` on each `apply_policy`.
    #[cfg(feature = "operator-cli")]
    pub targets_rx:
        tokio::sync::watch::Receiver<std::sync::Arc<Vec<crate::normalizer::CompiledTarget>>>,
    #[cfg(feature = "operator-cli")]
    pub ai_guard_state: std::sync::Arc<parking_lot::RwLock<crate::ai_guard::StateMap>>,
    /// Phase 3b.5 — needed by DoctorAiGuardReport handler.
    #[cfg(feature = "operator-cli")]
    pub parsers: std::sync::Arc<
        parking_lot::RwLock<Vec<std::sync::Arc<dyn crate::ai_guard::parser::AiGuardParser>>>,
    >,
    #[cfg(feature = "operator-cli")]
    pub ext_scripts: crate::ai_guard::ExtScriptRegistry,
    #[cfg(feature = "operator-cli")]
    pub rubric: crate::ai_guard::RubricHandle,
}

/// Shared dispatch logic. Returns the `Response` for a given `Request`.
/// Both platform `serve` functions call this to avoid duplicating logic.
async fn handle(ctx: &ControlContext, req: Request) -> Response {
    match req {
        Request::Stats => Response {
            ok: true,
            stats: Some(ctx.stats.snapshot()),
            apply_policy: None,
            policy_status: None,
            targets: None,
            risk: None,
            doctor_ai_guard: None,
            error: None,
        },
        Request::ApplyPolicy { response } => {
            let outcome = apply(&ctx.apply_ctx, &response).await;
            match outcome {
                ApplyOutcome::Accepted {
                    applied_policy_version,
                } => Response {
                    ok: true,
                    stats: None,
                    apply_policy: Some(ApplyPolicyResult::Accepted {
                        applied_policy_version,
                    }),
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    error: None,
                },
                ApplyOutcome::Rejected { reason } => Response {
                    ok: false,
                    stats: None,
                    apply_policy: Some(ApplyPolicyResult::Rejected { reason }),
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    error: None,
                },
                ApplyOutcome::Internal { detail } => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    error: Some(format!("internal: {detail}")),
                },
            }
        }
        Request::PolicyStatus => {
            let last_applied = ctx
                .apply_ctx
                .cache
                .lock()
                .host_meta_get()
                .map(|m| m.last_applied_policy_version)
                .unwrap_or(0);
            let valid_until_snapshot = *ctx.active_valid_until.read();
            let valid_until_str = valid_until_snapshot.and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            });
            let expired = valid_until_snapshot
                .map(|t| time::OffsetDateTime::now_utc() >= t)
                .unwrap_or(false);
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: Some(PolicyStatusPayload {
                    last_applied_policy_version: last_applied,
                    active_envelope_valid_until: valid_until_str,
                    policy_expired_active: expired,
                }),
                targets: None,
                risk: None,
                doctor_ai_guard: None,
                error: None,
            }
        }
        #[cfg(feature = "operator-cli")]
        Request::Targets => {
            let snapshot = ctx.targets_rx.borrow().clone();
            let summaries = snapshot
                .iter()
                .map(|t| TargetSummary {
                    id: t.id.clone(),
                    tier: t.tier,
                    globs: t.globs.iter().map(|g| g.pattern().to_string()).collect(),
                })
                .collect();
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: Some(TargetsPayload { targets: summaries }),
                risk: None,
                doctor_ai_guard: None,
                error: None,
            }
        }
        #[cfg(feature = "operator-cli")]
        Request::ReloadPolicy => {
            // send_modify always notifies receivers, even with no value change —
            // policy_reload_task wakes and re-reads policy.yaml from disk.
            ctx.apply_ctx.policy_version_tx.send_modify(|_| {});
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                doctor_ai_guard: None,
                error: None,
            }
        }
        #[cfg(feature = "operator-cli")]
        Request::Risk { tool } => {
            let snapshot = ctx.ai_guard_state.read();
            let mut assessments: Vec<RiskSummary> = snapshot
                .iter()
                .filter(|((t, _scope, _pid), _)| match tool {
                    Some(filter) => *t == filter,
                    None => true,
                })
                .map(|((t, scope, _pid), cached)| {
                    let last = cached
                        .last_assessed_ts
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default();
                    RiskSummary {
                        tool: *t,
                        scope: scope.clone(),
                        score: cached.score,
                        bucket: cached.bucket,
                        reasons_count: cached.reasons_count,
                        last_assessed_ts: last,
                    }
                })
                .collect();
            assessments.sort_by(|a, b| {
                serde_json::to_string(&a.tool)
                    .unwrap_or_default()
                    .cmp(&serde_json::to_string(&b.tool).unwrap_or_default())
            });
            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: Some(RiskPayload { assessments }),
                doctor_ai_guard: None,
                error: None,
            }
        }
        #[cfg(feature = "operator-cli")]
        Request::DoctorAiGuardReport => {
            // Parsers snapshot (clone the Arc list — small).
            let parsers_snapshot: Vec<std::sync::Arc<dyn crate::ai_guard::parser::AiGuardParser>> =
                ctx.parsers.read().clone();
            // Resolve home_dir consistently with runtime + reload.
            let home_dir = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("/"));
            let parsers: Vec<ParserInfo> = parsers_snapshot
                .iter()
                .map(|p| ParserInfo {
                    tool: p.tool(),
                    scope: p.scope(),
                    watched_path_count: p.watched_paths(&home_dir).len(),
                })
                .collect();

            // Per-repo summary — derive from parsers' scopes.
            let mut per_repo = PerRepoSummary::default();
            for p in &parsers_snapshot {
                if let sigil_core::event::AiGuardScope::Project { .. } = p.scope() {
                    match p.tool() {
                        sigil_core::event::AiTool::ContinueDev => per_repo.continue_dev += 1,
                        sigil_core::event::AiTool::ClaudeCode => per_repo.claude_code += 1,
                        sigil_core::event::AiTool::Codex => per_repo.codex += 1,
                        _ => {}
                    }
                }
            }

            // Rule packs — downcast via as_any() to identify RulePackParser.
            let mut rule_packs: Vec<RulePackInfo> = Vec::new();
            for p in &parsers_snapshot {
                if let Some(rpp) = p
                    .as_any()
                    .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                {
                    rule_packs.push(RulePackInfo {
                        id: rpp.pack.id.clone(),
                        loaded: true,
                        skip_reason: None,
                    });
                }
            }

            // Ext-script summary.
            let ext_map = ctx.ext_scripts.read();
            let mut unique: std::collections::BTreeSet<std::path::PathBuf> =
                std::collections::BTreeSet::new();
            let parser_entries = ext_map.len();
            for v in ext_map.values() {
                for p in v {
                    unique.insert(p.clone());
                }
            }
            drop(ext_map);
            let ext_scripts_summary = ExtScriptSummary {
                unique_paths: unique.len(),
                parser_entries,
            };

            // Latest risk — same shape as Risk handler.
            let snapshot = ctx.ai_guard_state.read();
            let mut latest_risk: Vec<RiskSummary> = snapshot
                .iter()
                .map(|((t, scope, _pid), cached)| {
                    let last = cached
                        .last_assessed_ts
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default();
                    RiskSummary {
                        tool: *t,
                        scope: scope.clone(),
                        score: cached.score,
                        bucket: cached.bucket,
                        reasons_count: cached.reasons_count,
                        last_assessed_ts: last,
                    }
                })
                .collect();
            drop(snapshot);
            latest_risk.sort_by(|a, b| {
                serde_json::to_string(&a.tool)
                    .unwrap_or_default()
                    .cmp(&serde_json::to_string(&b.tool).unwrap_or_default())
            });

            // Effective rubric.
            let rubric_snapshot = ctx.rubric.read().clone();
            let mut effective_rubric: Vec<RubricEntry> = rubric_snapshot
                .weights
                .iter()
                .map(|(k, w)| RubricEntry {
                    kind_key: k.to_string(),
                    weight: *w,
                    overridden: rubric_snapshot.overridden.contains(k),
                })
                .collect();
            // Sort: weight DESC then kind_key alpha for stable display.
            effective_rubric.sort_by(|a, b| {
                b.weight
                    .partial_cmp(&a.weight)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.kind_key.cmp(&b.kind_key))
            });

            Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                doctor_ai_guard: Some(DoctorAiGuardReport {
                    parsers,
                    per_repo,
                    rule_packs,
                    ext_scripts: ext_scripts_summary,
                    latest_risk,
                    effective_rubric,
                    unknown_override_keys: rubric_snapshot.unknown_override_keys.clone(),
                }),
                error: None,
            }
        }
        // The operator-cli request variants always exist on the wire (they live
        // in sigil-core::control_proto), but their handlers compile only with
        // the `operator-cli` feature. In a hardened build without it, reject.
        #[cfg(not(feature = "operator-cli"))]
        Request::Targets
        | Request::ReloadPolicy
        | Request::Risk { .. }
        | Request::DoctorAiGuardReport => Response {
            ok: false,
            stats: None,
            apply_policy: None,
            policy_status: None,
            targets: None,
            risk: None,
            doctor_ai_guard: None,
            error: Some("operator-cli feature not enabled in this build".into()),
        },
    }
}

#[cfg(unix)]
pub async fn serve(socket_path: &Path, ctx: Arc<ControlContext>) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    // Lock the control socket to owner+group rw, no world access (issue #4). The
    // agent runs as root; group ownership (root by default; `sigil` under the
    // future hardened install, epic #10) gates non-root control access. Set this
    // deterministically rather than relying on the process umask.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    }
    tracing::info!(path = ?socket_path, "control IPC listening");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "control IPC accept failed");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let (rd, mut wr) = stream.into_split();
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(line.trim()) {
                Ok(req) => handle(&ctx, req).await,
                Err(e) => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    error: Some(e.to_string()),
                },
            };
            if let Ok(json) = serde_json::to_string(&resp) {
                let _ = wr.write_all(json.as_bytes()).await;
                let _ = wr.write_all(b"\n").await;
            }
        });
    }
}

#[cfg(windows)]
pub async fn serve(pipe_name: &str, ctx: Arc<ControlContext>) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .access_inbound(true)
            .access_outbound(true)
            .create(pipe_name)?;
        server.connect().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let (rd, mut wr) = tokio::io::split(server);
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(line.trim()) {
                Ok(req) => handle(&ctx, req).await,
                Err(e) => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
                    risk: None,
                    doctor_ai_guard: None,
                    error: Some(e.to_string()),
                },
            };
            if let Ok(json) = serde_json::to_string(&resp) {
                let _ = wr.write_all(json.as_bytes()).await;
                let _ = wr.write_all(b"\n").await;
            }
        });
    }
}
