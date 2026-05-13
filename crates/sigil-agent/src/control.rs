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
use std::sync::Arc;

use crate::policy_apply::{apply, ApplyContext, ApplyOutcome};

/// Default control-socket path on Unix. `sigil run` binds it; `sigil show
/// stats` and `sigil-sender` connect to it.
pub fn default_control_socket() -> std::path::PathBuf {
    "/var/run/sigil/control.sock".into()
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
    pub targets_rx: tokio::sync::watch::Receiver<
        std::sync::Arc<Vec<crate::normalizer::CompiledTarget>>,
    >,
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
                    error: None,
                },
                ApplyOutcome::Rejected { reason } => Response {
                    ok: false,
                    stats: None,
                    apply_policy: Some(ApplyPolicyResult::Rejected { reason }),
                    policy_status: None,
                    targets: None,
                    error: None,
                },
                ApplyOutcome::Internal { detail } => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    targets: None,
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
}
