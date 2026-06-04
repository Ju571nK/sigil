//! Stage 2 (#100): hook-decide.sock request/response listener. Distinct from
//! the one-way `hook_listener` — here the agent MUST answer, and a deny is
//! recorded reliably (awaited) before the verdict is returned.
use crate::hook_deny::DenyEvaluator;
use crate::hook_listener::to_event;
use crate::state_task::CommittableEvent;
use sigil_core::event::{
    Evidence, HookDecisionEvidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use sigil_core::hook_proto::{
    Decision, EnforcementMode, HookAction, HookDecisionRequest, HookDecisionResponse, HookEnvelope,
    HookMsgType, HookVerdict, HOOK_PROTOCOL_VERSION,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Semaphore};

// Half of hook_listener's 32: two-way tasks hold the permit longer (awaited deny send before responding).
const MAX_INFLIGHT: usize = 16;
const MAX_LINE: u64 = 1024 * 1024;

#[cfg(unix)]
pub async fn serve(
    socket: PathBuf,
    tx: mpsc::Sender<CommittableEvent>,
    host_id: String,
    evaluator: Arc<DenyEvaluator>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }
    if let Some(p) = socket.parent() {
        std::fs::create_dir_all(p)?;
    }
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    tracing::info!(path = ?socket, "hook-decide IPC listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "hook-decide accept failed");
                continue;
            }
        };
        // Overload: drop the connection. The hook treats no-answer-within-deadline
        // as the no-verdict case and applies its local on_failure (fail-open default).
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("hook-decide overload: dropping (fail-open at hook)");
                drop(stream);
                continue;
            }
        };
        let peer_uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
        let tx = tx.clone();
        let host_id = host_id.clone();
        let evaluator = evaluator.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut line = String::new();
            // Use take() for bounded read then recover the stream via into_inner chain.
            // BufReader<Take<UnixStream>> -> into_inner() -> Take<UnixStream> -> into_inner() -> UnixStream.
            use tokio::io::AsyncReadExt;
            let mut rd = BufReader::new(stream.take(MAX_LINE));
            if rd.read_line(&mut line).await.is_err() {
                return;
            }
            let req: HookDecisionRequest = match serde_json::from_str(line.trim()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = ?e, "hook-decide: malformed request");
                    return;
                }
            };
            // Recover the raw stream to write the response.
            let mut stream = rd.into_inner().into_inner();

            // 1) Observe event (best-effort, like Stage 1's one-way path).
            let action = req.invocation.action.clone();
            let inv = req.invocation.clone();
            let observe_env = HookEnvelope {
                protocol_version: HOOK_PROTOCOL_VERSION,
                msg_type: HookMsgType::HookInvocation,
                request_id: req.request_id,
                sent_at_unix_ms: req.sent_at_unix_ms,
                payload: inv,
            };
            let observe_ev = to_event(observe_env, peer_uid, &host_id);
            let _ = tx.try_send(CommittableEvent {
                event: observe_ev,
                new_hash: None,
                path_for_db: PathBuf::new(),
                target_id: String::new(),
            });

            // 2) Decide.
            let verdict = match evaluator.evaluate(&action) {
                Some((rule_id, reason)) => {
                    // Record HookDecision(deny) RELIABLY before responding.
                    let ev = decision_event(
                        &req.invocation,
                        peer_uid,
                        &host_id,
                        "deny",
                        Some(rule_id.clone()),
                        Some(reason.clone()),
                    );
                    let _ = tx
                        .send(CommittableEvent {
                            event: ev,
                            new_hash: None,
                            path_for_db: PathBuf::new(),
                            target_id: String::new(),
                        })
                        .await;
                    HookVerdict {
                        decision: Decision::Deny { rule_id, reason },
                        enforcement_mode: EnforcementMode::Enforce,
                    }
                }
                None => HookVerdict {
                    decision: Decision::Allow,
                    enforcement_mode: EnforcementMode::Enforce,
                },
            };

            let resp = HookDecisionResponse {
                protocol_version: HOOK_PROTOCOL_VERSION,
                request_id: req.request_id,
                verdict,
            };
            if let Ok(mut s) = serde_json::to_string(&resp) {
                s.push('\n');
                let _ = stream.write_all(s.as_bytes()).await;
                let _ = stream.flush().await;
                // Signal EOF promptly so the client's read_line returns without
                // waiting on drop.
                let _ = stream.shutdown().await;
            }
        });
    }
}

fn decision_event(
    inv: &sigil_core::hook_proto::HookInvocation,
    peer_uid: u32,
    host_id: &str,
    // decision is "deny" in slice 1; a typed enum can replace the &str if allow/degradation outcomes are ever recorded.
    decision: &str,
    rule_id: Option<String>,
    deny_reason: Option<String>,
) -> sigil_core::event::Event {
    let (kind, hash, preview) = match &inv.action {
        HookAction::Bash {
            command_hash,
            command_preview,
        } => ("bash", command_hash.clone(), command_preview.clone()),
        HookAction::FileEdit {
            path_hash,
            path_preview,
            ..
        } => ("file_edit", path_hash.clone(), path_preview.clone()),
        HookAction::McpCall {
            args_hash,
            args_preview,
            ..
        } => ("mcp_call", args_hash.clone(), args_preview.clone()),
        // slice 1: HookDecisionEvidence has no other_label; the tool name for Other actions is not recorded here (follow-on).
        HookAction::Other {
            detail_hash,
            detail_preview,
            ..
        } => ("other", detail_hash.clone(), detail_preview.clone()),
    };
    sigil_core::event::Event {
        schema_version: SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        host_id: host_id.to_string(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Warn,
        source: SourceKind::AgentHook,
        subject: Subject::Self_,
        evidence: Evidence::HookDecision(HookDecisionEvidence {
            agent: inv.agent,
            peer_uid,
            agent_session_id: inv.agent_session_id.clone(),
            tool_use_id: inv.tool_use_id.clone(),
            action_kind: kind.to_string(),
            action_hash: hash,
            action_preview: preview,
            decision: decision.to_string(),
            rule_id,
            deny_reason,
            enforcement_mode: "enforce".to_string(),
            capture_level: crate::hook_listener::enum_str(&inv.capture_level),
        }),
        target_id: None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sigil_core::hook_proto::{CaptureLevel, CaptureStatus, HookInvocation};
    use sigil_core::policy::{DenyRule, HookActionMatch, Matcher};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn req(cmd: &str) -> HookDecisionRequest {
        HookDecisionRequest {
            protocol_version: HOOK_PROTOCOL_VERSION,
            request_id: uuid::Uuid::now_v7(),
            sent_at_unix_ms: 0,
            invocation: HookInvocation {
                agent: sigil_core::event::AiTool::ClaudeCode,
                agent_session_id: None,
                tool_use_id: None,
                action: HookAction::Bash {
                    command_hash: "ab".repeat(32),
                    command_preview: Some(cmd.into()),
                },
                capture_level: CaptureLevel::Redacted,
                capture_status: CaptureStatus::Ok,
                cwd: None,
            },
            deadline_ms: 250,
        }
    }

    async fn round_trip(
        socket: &std::path::Path,
        request: &HookDecisionRequest,
    ) -> HookDecisionResponse {
        let mut s = tokio::net::UnixStream::connect(socket).await.unwrap();
        let mut line = serde_json::to_string(request).unwrap();
        line.push('\n');
        s.write_all(line.as_bytes()).await.unwrap();
        let mut resp = String::new();
        BufReader::new(s).read_line(&mut resp).await.unwrap();
        serde_json::from_str(resp.trim()).unwrap()
    }

    #[tokio::test]
    async fn deny_matches_and_records_decision_then_allow_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("hook-decide.sock");
        let (tx, mut rx) = mpsc::channel(16);
        let ev = Arc::new(
            DenyEvaluator::new(&[DenyRule {
                id: "no-rm".into(),
                match_: HookActionMatch::Bash {
                    command: Matcher::Regex {
                        pattern: r"rm\s+-rf".into(),
                    },
                },
            }])
            .unwrap(),
        );
        let sock2 = socket.clone();
        tokio::spawn(async move {
            let _ = serve(sock2, tx, "host-x".into(), ev).await;
        });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // DENY
        let r = round_trip(&socket, &req("rm -rf /")).await;
        match r.verdict.decision {
            Decision::Deny { rule_id, .. } => assert_eq!(rule_id, "no-rm"),
            _ => panic!("expected deny"),
        }
        // Observe (try_send) happens before the awaited decision send, so the
        // order is deterministic: invocation first, decision second.
        let e1 = rx.recv().await.unwrap();
        assert!(
            matches!(e1.event.evidence, Evidence::HookInvocation(_)),
            "observe recorded first"
        );
        let e2 = rx.recv().await.unwrap();
        assert!(
            matches!(e2.event.evidence, Evidence::HookDecision(_)),
            "decision recorded second"
        );

        // ALLOW
        let r = round_trip(&socket, &req("ls -la")).await;
        assert!(matches!(r.verdict.decision, Decision::Allow));
    }
}
