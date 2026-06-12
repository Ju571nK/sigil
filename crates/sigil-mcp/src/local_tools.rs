use crate::local::LocalUpstream;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use serde::Deserialize;
use sigil_core::assess::AssessInput;
use std::sync::Arc;

fn ok(v: serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(v.to_string())]))
}

/// Parameters for the `assess` tool. All fields are optional; exactly one
/// "mode" must be provided: either `command` (command mode) or `mcp_server`
/// (MCP server definition mode). Passing neither or both is an invalid-params
/// error — the tool never silently produces an Allow.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AssessParams {
    /// Shell command to pre-flight (command mode).
    pub command: Option<String>,
    /// Arguments for the shell command (command mode, optional).
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// MCP server definition JSON object to pre-flight (mcp_server mode).
    pub mcp_server: Option<serde_json::Value>,
    /// Name of the MCP server (required when `mcp_server` is provided).
    pub server_name: Option<String>,
}

#[derive(Clone)]
pub struct SigilLocal {
    upstream: Arc<LocalUpstream>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl SigilLocal {
    pub fn new(upstream: Arc<LocalUpstream>) -> Self {
        Self {
            upstream,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "This machine's AI-tool risk headline: per (tool, scope) risk band + score, \
                          plus reasons_count and last-assessed time. Use for 'what's my AI risk?'."
    )]
    async fn my_risk(&self) -> Result<CallToolResult, McpError> {
        let r = self.upstream.doctor_report().await?;
        ok(serde_json::json!({ "latest_risk": r.latest_risk }))
    }

    #[tool(
        description = "Why this machine is rated the way it is: effective rubric (weights/overrides), \
                          active parsers per (tool, scope), loaded rule packs, unknown override keys."
    )]
    async fn my_guard_detail(&self) -> Result<CallToolResult, McpError> {
        let r = self.upstream.doctor_report().await?;
        ok(serde_json::json!({
            "effective_rubric": r.effective_rubric,
            "parsers": r.parsers,
            "rule_packs": r.rule_packs,
            "unknown_override_keys": r.unknown_override_keys,
        }))
    }

    #[tool(
        description = "Concrete surface Sigil found on this machine: per-repo workspace discovery \
                          counts per tool, and external hook-script watch summary."
    )]
    async fn my_findings(&self) -> Result<CallToolResult, McpError> {
        let r = self.upstream.doctor_report().await?;
        ok(serde_json::json!({ "per_repo": r.per_repo, "ext_scripts": r.ext_scripts }))
    }

    #[tool(
        description = "Pre-flight a proposed shell command or a single MCP server definition \
                       against THIS host's currently loaded Sigil policy (rubric + deny rules). \
                       Returns a risk band, score, reasons, any deny-rule match, and a decision \
                       (allow/warn/deny). Read-only; does not execute anything."
    )]
    async fn assess(
        &self,
        Parameters(p): Parameters<AssessParams>,
    ) -> Result<CallToolResult, McpError> {
        let input = match (p.command, p.mcp_server) {
            // Command mode.
            (Some(command), None) => AssessInput::Command {
                command,
                args: p.args.unwrap_or_default(),
            },
            // MCP server definition mode.
            (None, Some(def)) => {
                if !def.is_object() {
                    return Err(McpError::invalid_params(
                        "`mcp_server` must be a JSON object",
                        None,
                    ));
                }
                let server_name = p.server_name.ok_or_else(|| {
                    McpError::invalid_params(
                        "`server_name` is required when `mcp_server` is provided",
                        None,
                    )
                })?;
                AssessInput::McpServer {
                    server_name,
                    definition: def,
                }
            }
            // Neither provided.
            (None, None) => {
                return Err(McpError::invalid_params(
                    "exactly one of `command` or `mcp_server` must be provided",
                    None,
                ));
            }
            // Both provided.
            (Some(_), Some(_)) => {
                return Err(McpError::invalid_params(
                    "exactly one of `command` or `mcp_server` must be provided (not both)",
                    None,
                ));
            }
        };

        let verdict = self.upstream.assess(input).await?;
        ok(serde_json::to_value(&verdict)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?)
    }
}

#[tool_handler]
impl ServerHandler for SigilLocal {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            // Single-host identity: this server only ever exposes THIS machine's
            // posture. Operators who want the fleet run `sigil-fleet` instead.
            server_info: Implementation {
                name: "sigil-check".to_string(),
                ..Implementation::from_build_env()
            },
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "Read-only view of THIS machine's Sigil AI Guard posture (no fleet, no server). \
                 Start with my_risk, explain with my_guard_detail, list findings with my_findings. \
                 Use assess to pre-flight a proposed shell command or MCP server definition \
                 against the loaded policy before executing it. \
                 There are no write or remediation tools."
                    .to_string(),
            ),
            ..Default::default()
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sigil_core::assess::{AssessVerdict, Decision};
    use sigil_core::control_proto::{DoctorAiGuardReport, PerRepoSummary, Response};
    use sigil_core::event::AiGuardBucket;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// Stands up a canned UnixListener that replies to a single
    /// `DoctorAiGuardReport` request, mirroring `local.rs`'s test harness.
    fn canned_agent(socket: std::path::PathBuf) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            let resp = Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                error: None,
                doctor_ai_guard: Some(DoctorAiGuardReport {
                    parsers: vec![],
                    rule_packs: vec![],
                    ext_scripts: Default::default(),
                    per_repo: PerRepoSummary {
                        continue_dev: 0,
                        claude_code: 2,
                        codex: 0,
                    },
                    latest_risk: vec![],
                    effective_rubric: vec![],
                    unknown_override_keys: vec![],
                }),
                assess_verdict: None,
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        })
    }

    fn text(res: &CallToolResult) -> String {
        res.content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect::<Vec<_>>()
            .join("")
    }

    #[tokio::test]
    async fn my_risk_returns_latest_risk() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let srv = canned_agent(socket.clone());
        let local = SigilLocal::new(Arc::new(LocalUpstream::new(socket)));
        let res = local.my_risk().await.unwrap();
        assert_eq!(res.is_error, Some(false));
        assert!(text(&res).contains("latest_risk"));
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn my_findings_returns_per_repo() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let srv = canned_agent(socket.clone());
        let local = SigilLocal::new(Arc::new(LocalUpstream::new(socket)));
        let res = local.my_findings().await.unwrap();
        assert_eq!(res.is_error, Some(false));
        assert!(text(&res).contains("per_repo"));
        srv.await.unwrap();
    }

    /// Stands up a canned UnixListener that replies to a single `Assess`
    /// request with a known `AssessVerdict`.
    fn canned_assess_agent(
        socket: std::path::PathBuf,
        verdict: AssessVerdict,
    ) -> tokio::task::JoinHandle<()> {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            let resp = Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                error: None,
                doctor_ai_guard: None,
                assess_verdict: Some(verdict),
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        })
    }

    /// Canned upstream returns a known AssessVerdict; the tool returns a
    /// JSON result containing the expected decision and band.
    #[tokio::test]
    async fn assess_tool_returns_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("assess_tool.sock");
        let expected = AssessVerdict {
            bucket: AiGuardBucket::High,
            score: 7.5,
            reasons: vec![],
            deny_match: None,
            decision: Decision::Deny,
        };
        let srv = canned_assess_agent(socket.clone(), expected);
        let local = SigilLocal::new(Arc::new(LocalUpstream::new(socket)));
        let res = local
            .assess(Parameters(AssessParams {
                command: Some("rm".to_string()),
                args: Some(vec!["-rf".to_string(), "/".to_string()]),
                mcp_server: None,
                server_name: None,
            }))
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
        let body = text(&res);
        assert!(body.contains("deny"), "expected 'deny' in: {body}");
        assert!(body.contains("high"), "expected 'high' band in: {body}");
        srv.await.unwrap();
    }

    /// Neither `command` nor `mcp_server` provided → invalid-params McpError.
    /// Both provided → invalid-params McpError.
    #[tokio::test]
    async fn assess_tool_requires_exactly_one_mode() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("xor_test.sock");
        // No socket needed — validation fires before any IPC.
        let local = SigilLocal::new(Arc::new(LocalUpstream::new(socket)));

        // Neither mode.
        let err = local
            .assess(Parameters(AssessParams {
                command: None,
                args: None,
                mcp_server: None,
                server_name: None,
            }))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("exactly one"),
            "expected 'exactly one' in: {msg}"
        );

        // Both modes simultaneously.
        let err2 = local
            .assess(Parameters(AssessParams {
                command: Some("ls".to_string()),
                args: None,
                mcp_server: Some(serde_json::json!({"transport": "stdio"})),
                server_name: Some("x".to_string()),
            }))
            .await
            .unwrap_err();
        let msg2 = format!("{err2:?}");
        assert!(
            msg2.contains("exactly one"),
            "expected 'exactly one' in: {msg2}"
        );
    }

    /// `mcp_server` is not a JSON object (string/array) → invalid-params McpError.
    #[tokio::test]
    async fn assess_tool_mcp_non_object_errors() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("non_obj_test.sock");
        let local = SigilLocal::new(Arc::new(LocalUpstream::new(socket)));

        // JSON string — not an object.
        let err = local
            .assess(Parameters(AssessParams {
                command: None,
                args: None,
                mcp_server: Some(serde_json::Value::String("bad".to_string())),
                server_name: Some("s".to_string()),
            }))
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("object"),
            "expected 'object' error msg in: {msg}"
        );

        // JSON array — also not an object.
        let err2 = local
            .assess(Parameters(AssessParams {
                command: None,
                args: None,
                mcp_server: Some(serde_json::json!(["a", "b"])),
                server_name: Some("s".to_string()),
            }))
            .await
            .unwrap_err();
        let msg2 = format!("{err2:?}");
        assert!(
            msg2.contains("object"),
            "expected 'object' error msg in: {msg2}"
        );
    }
}
