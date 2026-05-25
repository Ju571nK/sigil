//! Control IPC: UDS on Unix, Named Pipe on Windows.
//!
//! Phase 1 supports a single command: `{"cmd":"stats"}` returning the current
//! Heartbeat-equivalent payload as JSON.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sigil_core::policy::signed_envelope::SignedPolicyResponse;
use sigil_core::stats::{Stats, StatsSnapshot};
use sigil_core::PolicySignatureInvalidReason;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use crate::policy_apply::{apply, ApplyContext, ApplyOutcome};

/// Default control-socket path. As root, the system path `/var/run/sigil`
/// (matches the systemd unit's `RuntimeDirectory=`). A non-root agent (macOS,
/// non-root Linux — e.g. the 2-machine test) can't write there, so fall back
/// to `$XDG_RUNTIME_DIR/sigil` (else `$TMPDIR`/`/tmp/sigil-<uid>`), keeping the
/// control plane usable without elevation. Override with `--control-socket`.
/// `sigil run` binds it; `sigil show stats` and `sigil-sender` connect to it.
/// On Windows the named pipe is used instead and this value is ignored.
pub fn default_control_socket() -> PathBuf {
    resolve_control_socket(
        is_root(),
        std::env::var("XDG_RUNTIME_DIR")
            .ok()
            .filter(|s| !s.is_empty()),
        std::env::var("TMPDIR").ok().filter(|s| !s.is_empty()),
        current_uid(),
    )
}

/// Pure resolver for [`default_control_socket`] — split out so the
/// root/non-root/XDG/TMPDIR branches can be unit-tested without touching the
/// process euid or environment.
fn resolve_control_socket(
    is_root: bool,
    xdg_runtime: Option<String>,
    tmpdir: Option<String>,
    uid: u32,
) -> PathBuf {
    if is_root {
        return PathBuf::from("/var/run/sigil/control.sock");
    }
    if let Some(dir) = xdg_runtime {
        return PathBuf::from(dir).join("sigil").join("control.sock");
    }
    let base = tmpdir.unwrap_or_else(|| "/tmp".to_string());
    PathBuf::from(base)
        .join(format!("sigil-{uid}"))
        .join("control.sock")
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Existing Phase 1 command — unchanged on the wire.
    #[serde(rename = "stats")]
    Stats,
    /// Plan B `sigil-sender` hands a verified envelope here for application.
    ApplyPolicy {
        /// The full server response — agent re-verifies independently.
        response: SignedPolicyResponse,
    },
    /// Operator + sender introspection: returns the agent's current
    /// `last_applied_policy_version`, the active `valid_until`, and whether
    /// the active policy is currently expired.
    PolicyStatus,
    /// Operator introspection: returns the agent's currently-active watch
    /// targets and their compiled glob patterns.
    #[cfg(feature = "operator-cli")]
    Targets,
    /// Operator action: re-read the policy file (after a hand-edit) without
    /// verifying a signed envelope. Re-uses the existing live-reload pipeline
    /// by nudging the policy-version watch channel.
    #[cfg(feature = "operator-cli")]
    ReloadPolicy,
    /// Operator introspection: returns the latest AI Guard risk assessment
    /// for each tool (or a single tool if `tool` is set).
    #[cfg(feature = "operator-cli")]
    Risk {
        tool: Option<sigil_core::event::AiTool>,
    },
    /// Operator introspection: returns a snapshot of the AI Guard
    /// subsystem state for `sigil doctor`. Phase 3b.5.
    #[cfg(feature = "operator-cli")]
    DoctorAiGuardReport,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub ok: bool,
    pub stats: Option<StatsSnapshot>,
    /// Present iff the request was `ApplyPolicy`.
    pub apply_policy: Option<ApplyPolicyResult>,
    /// Present iff the request was `PolicyStatus`.
    pub policy_status: Option<PolicyStatusPayload>,
    /// Present iff the request was `Targets` (Phase 2 operator introspection).
    pub targets: Option<TargetsPayload>,
    /// Present iff the request was `Risk`.
    pub risk: Option<RiskPayload>,
    /// Present iff the request was `DoctorAiGuardReport`. Phase 3b.5.
    #[cfg(feature = "operator-cli")]
    pub doctor_ai_guard: Option<DoctorAiGuardReport>,
    pub error: Option<String>,
}

/// Outcome of an `apply_policy` request.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApplyPolicyResult {
    /// Verifier accepted; policy.yaml written; version advanced.
    Accepted {
        /// The new `last_applied_policy_version`.
        applied_policy_version: i64,
    },
    /// Verifier rejected. The wire-stable `reason` matches the
    /// `PolicySignatureInvalid` event variant emitted in parallel.
    Rejected {
        /// Which check failed.
        reason: PolicySignatureInvalidReason,
    },
}

/// Snapshot of the agent's current policy state.
#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyStatusPayload {
    pub last_applied_policy_version: i64,
    /// RFC 3339; `None` if no envelope has ever been applied.
    pub active_envelope_valid_until: Option<String>,
    /// `true` iff `now >= active_envelope_valid_until`.
    pub policy_expired_active: bool,
}

/// Summary of one active watch target — what the agent is currently watching
/// post-policy-merge + post-canonicalization.
#[derive(Serialize, Deserialize, Debug)]
pub struct TargetSummary {
    pub id: String,
    pub tier: sigil_core::policy::Tier,
    pub globs: Vec<String>,
}

/// Payload for the `targets` control-IPC response: the agent's currently-active
/// compiled targets.
#[derive(Serialize, Deserialize, Debug)]
pub struct TargetsPayload {
    pub targets: Vec<TargetSummary>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RiskPayload {
    pub assessments: Vec<RiskSummary>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RiskSummary {
    pub tool: sigil_core::event::AiTool,
    pub scope: sigil_core::event::AiGuardScope,
    pub score: f32,
    pub bucket: sigil_core::event::AiGuardBucket,
    pub reasons_count: usize,
    /// RFC 3339.
    pub last_assessed_ts: String,
}

/// Phase 3b.5 — serializable snapshot of the agent's AI Guard subsystem
/// state, returned by `Request::DoctorAiGuardReport` for `sigil doctor`.
#[derive(Serialize, Deserialize, Debug)]
#[cfg(feature = "operator-cli")]
pub struct DoctorAiGuardReport {
    /// Active parser instances. One entry per (tool, scope) pair.
    pub parsers: Vec<ParserInfo>,
    /// Discovered per-repo workspaces, count per tool.
    pub per_repo: PerRepoSummary,
    /// Loaded rule packs (3b.7). Skipped packs are not currently retained;
    /// only loaded ones are reported. Future enhancement may surface skip
    /// reasons from the loader.
    pub rule_packs: Vec<RulePackInfo>,
    /// External hook scripts (3b.3) currently being watched.
    pub ext_scripts: ExtScriptSummary,
    /// Latest risk assessment per (tool, scope) from ai_guard_state cache.
    pub latest_risk: Vec<RiskSummary>,
    /// Effective rubric — every kind_key with current weight + whether it
    /// came from an operator override.
    pub effective_rubric: Vec<RubricEntry>,
    /// Snake_case override keys the envelope referenced but didn't match
    /// any known kind. Surfaced by doctor as `[WARN]`.
    pub unknown_override_keys: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg(feature = "operator-cli")]
pub struct ParserInfo {
    pub tool: sigil_core::event::AiTool,
    pub scope: sigil_core::event::AiGuardScope,
    pub watched_path_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[cfg(feature = "operator-cli")]
pub struct PerRepoSummary {
    pub continue_dev: usize,
    pub claude_code: usize,
    pub codex: usize,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg(feature = "operator-cli")]
pub struct RulePackInfo {
    pub id: String,
    pub loaded: bool,
    /// `None` when loaded. Reserved for future surfacing of skip reasons.
    pub skip_reason: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[cfg(feature = "operator-cli")]
pub struct ExtScriptSummary {
    /// Total unique canonical script paths across all parsers.
    pub unique_paths: usize,
    /// Number of (tool, scope) entries that have at least one ext-script.
    pub parser_entries: usize,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg(feature = "operator-cli")]
pub struct RubricEntry {
    pub kind_key: String,
    pub weight: f32,
    pub overridden: bool,
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
            #[cfg(feature = "operator-cli")]
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
                    #[cfg(feature = "operator-cli")]
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
                    #[cfg(feature = "operator-cli")]
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
                    #[cfg(feature = "operator-cli")]
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
                #[cfg(feature = "operator-cli")]
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
                .filter(|((t, _scope), _)| match tool {
                    Some(filter) => *t == filter,
                    None => true,
                })
                .map(|((t, scope), cached)| {
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
                .map(|((t, scope), cached)| {
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
                    #[cfg(feature = "operator-cli")]
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
                    #[cfg(feature = "operator-cli")]
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

#[cfg(test)]
mod socket_path_tests {
    use super::resolve_control_socket;
    use std::path::PathBuf;

    #[test]
    fn root_uses_system_run_path() {
        assert_eq!(
            resolve_control_socket(
                true,
                Some("/run/user/1000".into()),
                Some("/tmp".into()),
                1000
            ),
            PathBuf::from("/var/run/sigil/control.sock")
        );
    }

    #[test]
    fn nonroot_prefers_xdg_runtime_dir() {
        assert_eq!(
            resolve_control_socket(
                false,
                Some("/run/user/501".into()),
                Some("/tmp".into()),
                501
            ),
            PathBuf::from("/run/user/501/sigil/control.sock")
        );
    }

    #[test]
    fn nonroot_without_xdg_uses_tmpdir_namespaced_by_uid() {
        assert_eq!(
            resolve_control_socket(false, None, Some("/custom/tmp".into()), 501),
            PathBuf::from("/custom/tmp/sigil-501/control.sock")
        );
    }

    #[test]
    fn nonroot_without_xdg_or_tmpdir_falls_back_to_slash_tmp() {
        assert_eq!(
            resolve_control_socket(false, None, None, 42),
            PathBuf::from("/tmp/sigil-42/control.sock")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
    use time::macros::datetime;

    fn sample_response() -> SignedPolicyResponse {
        SignedPolicyResponse {
            etag: "abc".into(),
            signed_envelope: SignedEnvelope {
                policy_version: 7,
                policy_bytes_b64: "AAA=".into(),
                valid_until: datetime!(2026-06-15 0:00 UTC),
                issued_at: datetime!(2026-05-15 8:00 UTC),
            },
            signature: "sig".into(),
            signing_pubkey_id: "k1".into(),
            applied_at: datetime!(2026-05-15 8:01 UTC),
        }
    }

    #[test]
    fn apply_policy_request_round_trips() {
        let req = Request::ApplyPolicy {
            response: sample_response(),
        };
        let s = serde_json::to_string(&req).unwrap();
        // The cmd discriminator MUST be exactly "apply_policy" (snake_case is
        // wrong here — the existing Phase 1 control protocol uses lowercase).
        assert!(s.contains("\"cmd\":\"apply_policy\""));
        let back: Request = serde_json::from_str(&s).unwrap();
        match back {
            Request::ApplyPolicy { response } => {
                assert_eq!(response.signed_envelope.policy_version, 7);
            }
            _ => panic!("expected ApplyPolicy, got {back:?}"),
        }
    }

    #[test]
    fn policy_status_request_round_trips() {
        let req = Request::PolicyStatus;
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"cmd\":\"policy_status\""));
        let _: Request = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn response_includes_optional_apply_policy_payload() {
        let r = Response {
            ok: true,
            stats: None,
            apply_policy: Some(ApplyPolicyResult::Accepted {
                applied_policy_version: 9,
            }),
            policy_status: None,
            targets: None,
            risk: None,
            #[cfg(feature = "operator-cli")]
            doctor_ai_guard: None,
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"apply_policy\""));
        assert!(s.contains("\"applied_policy_version\":9"));
    }

    #[test]
    fn response_apply_policy_rejected_carries_reason() {
        let r = Response {
            ok: false,
            stats: None,
            apply_policy: Some(ApplyPolicyResult::Rejected {
                reason: sigil_core::PolicySignatureInvalidReason::Expired,
            }),
            policy_status: None,
            targets: None,
            risk: None,
            #[cfg(feature = "operator-cli")]
            doctor_ai_guard: None,
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"reason\":\"expired\""));
    }

    #[test]
    fn response_with_targets_round_trips() {
        let resp = Response {
            ok: true,
            stats: None,
            apply_policy: None,
            policy_status: None,
            targets: Some(TargetsPayload {
                targets: vec![TargetSummary {
                    id: "tgt-1".into(),
                    tier: sigil_core::policy::Tier::Critical,
                    globs: vec!["/etc/foo.yaml".into(), "/var/log/bar/*.log".into()],
                }],
            }),
            risk: None,
            #[cfg(feature = "operator-cli")]
            doctor_ai_guard: None,
            error: None,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"targets\""));
        assert!(s.contains("\"tgt-1\""));
        assert!(
            s.contains("\"critical\""),
            "Tier::Critical serializes lowercase, got: {s}"
        );
        let back: Response = serde_json::from_str(&s).unwrap();
        assert!(back.targets.is_some());
        assert_eq!(back.targets.as_ref().unwrap().targets[0].id, "tgt-1");
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn request_targets_round_trips() {
        let req = Request::Targets;
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"cmd":"targets"}"#);
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::Targets));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn request_reload_policy_round_trips() {
        let req = Request::ReloadPolicy;
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"cmd":"reload_policy"}"#);
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::ReloadPolicy));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn request_risk_round_trips_no_filter() {
        let req = Request::Risk { tool: None };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"cmd\":\"risk\""), "got: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::Risk { tool: None }));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn request_risk_round_trips_with_tool_filter() {
        let req = Request::Risk {
            tool: Some(sigil_core::event::AiTool::ClaudeCode),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"tool\":\"claude_code\""), "got: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(
            back,
            Request::Risk {
                tool: Some(sigil_core::event::AiTool::ClaudeCode)
            }
        ));
    }

    #[cfg(feature = "operator-cli")]
    #[test]
    fn response_with_risk_payload_round_trips() {
        use sigil_core::event::{AiGuardBucket, AiGuardScope, AiTool};
        let resp = Response {
            ok: true,
            stats: None,
            apply_policy: None,
            policy_status: None,
            targets: None,
            risk: Some(RiskPayload {
                assessments: vec![RiskSummary {
                    tool: AiTool::Codex,
                    scope: AiGuardScope::UserGlobal,
                    score: 2.0,
                    bucket: AiGuardBucket::Medium,
                    reasons_count: 1,
                    last_assessed_ts: "2026-05-16T06:00:00Z".into(),
                }],
            }),
            doctor_ai_guard: None,
            error: None,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"risk\""));
        assert!(s.contains("\"tool\":\"codex\""));
        assert!(s.contains("\"bucket\":\"medium\""));
        let back: Response = serde_json::from_str(&s).unwrap();
        assert!(back.risk.is_some());
        assert_eq!(back.risk.as_ref().unwrap().assessments.len(), 1);
    }
}
