use crate::local::LocalUpstream;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use std::sync::Arc;

fn ok(v: serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(v.to_string())]))
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
    use sigil_core::control_proto::{DoctorAiGuardReport, PerRepoSummary, Response};
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
}
