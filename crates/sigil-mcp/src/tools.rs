use crate::upstream::Upstream;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct SigilFleet {
    upstream: Arc<Upstream>,
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HostIdParams {
    /// Stable host UUID (from list_hosts / fleet_risk).
    pub host_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EventIdParams {
    /// Event UUID (from query_events).
    pub event_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QueryEventsParams {
    /// Filter to these host UUIDs (repeatable). Empty = all hosts.
    #[serde(default)]
    pub host_id: Vec<String>,
    /// Only events at/after this RFC 3339 timestamp.
    pub since: Option<String>,
    /// Max events, 1..1000 (server default 100).
    pub limit: Option<u32>,
    /// Opaque pagination cursor (UUID) from a prior next_cursor.
    pub cursor: Option<String>,
}

fn ok(v: serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(v.to_string())]))
}

#[tool_router]
impl SigilFleet {
    pub fn new(upstream: Arc<Upstream>) -> Self {
        Self {
            upstream,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "List all hosts known to the fleet (id, hostname, last-seen).")]
    async fn list_hosts(&self) -> Result<CallToolResult, McpError> {
        ok(self.upstream.get("/v1/fleet/hosts", &[]).await?)
    }

    #[tool(description = "Get full posture detail for one host by its UUID.")]
    async fn get_host(
        &self,
        Parameters(p): Parameters<HostIdParams>,
    ) -> Result<CallToolResult, McpError> {
        ok(self
            .upstream
            .get(&format!("/v1/fleet/hosts/{}", p.host_id), &[])
            .await?)
    }

    #[tool(description = "Fleet-wide AI Guard risk index: per-host risk band and score.")]
    async fn fleet_risk(&self) -> Result<CallToolResult, McpError> {
        ok(self.upstream.get("/v1/fleet/risk", &[]).await?)
    }

    #[tool(description = "Fleet-wide policy compliance per host.")]
    async fn fleet_compliance(&self) -> Result<CallToolResult, McpError> {
        ok(self.upstream.get("/v1/fleet/compliance", &[]).await?)
    }

    #[tool(description = "Query posture events with optional host/time filters and pagination.")]
    async fn query_events(
        &self,
        Parameters(p): Parameters<QueryEventsParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut q: Vec<(&str, String)> = Vec::new();
        // The server reads `host_id` as a comma-separated filter (like
        // evidence_kind/severity/source), not repeated params — sending repeats
        // tripped its serde_urlencoded deserializer with "expected a sequence" (#73).
        if !p.host_id.is_empty() {
            q.push(("host_id", p.host_id.join(",")));
        }
        if let Some(s) = &p.since {
            q.push(("since", s.clone()));
        }
        if let Some(l) = p.limit {
            q.push(("limit", l.to_string()));
        }
        if let Some(c) = &p.cursor {
            q.push(("cursor", c.clone()));
        }
        ok(self.upstream.get("/v1/events", &q).await?)
    }

    #[tool(description = "Get one posture event by its UUID.")]
    async fn get_event(
        &self,
        Parameters(p): Parameters<EventIdParams>,
    ) -> Result<CallToolResult, McpError> {
        ok(self
            .upstream
            .get(&format!("/v1/events/{}", p.event_id), &[])
            .await?)
    }

    #[tool(description = "Get the active signed policy bundle the server serves to agents.")]
    async fn get_policy(&self) -> Result<CallToolResult, McpError> {
        ok(self.upstream.get("/v1/policy", &[]).await?)
    }

    #[tool(description = "Server metadata (version, build, capabilities).")]
    async fn server_meta(&self) -> Result<CallToolResult, McpError> {
        ok(self.upstream.get("/v1/meta", &[]).await?)
    }

    #[tool(description = "Server liveness check.")]
    async fn healthz(&self) -> Result<CallToolResult, McpError> {
        ok(self.upstream.get("/v1/healthz", &[]).await?)
    }
}

#[tool_handler]
impl ServerHandler for SigilFleet {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            // Operator-facing fleet view — distinct identity from the single-host
            // `sigil-check` (local) server so clients can tell the two apart.
            server_info: Implementation {
                name: "sigil-fleet".to_string(),
                ..Implementation::from_build_env()
            },
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "Read-only access to a Sigil fleet's security posture, for operators \
                 (run alongside sigil-server / sigil-manager). Survey with \
                 fleet_risk/list_hosts, drill in with get_host, investigate over time \
                 with query_events. There are no write or remediation tools — this \
                 server cannot change anything."
                    .to_string(),
            ),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::{Method::GET, MockServer};
    use serde_json::json;
    use std::sync::Arc;

    fn fleet(base_url: String) -> SigilFleet {
        SigilFleet::new(Arc::new(crate::upstream::Upstream::for_test(base_url)))
    }

    #[tokio::test]
    async fn list_hosts_hits_endpoint_and_returns_text() {
        let server = MockServer::start_async().await;
        let m = server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/fleet/hosts");
                then.status(200)
                    .json_body(json!([{"host_id": "abc", "hostname": "ju571n"}]));
            })
            .await;

        let res = fleet(server.base_url()).list_hosts().await.unwrap();

        m.assert_async().await;
        assert_eq!(res.is_error, Some(false));
    }

    #[tokio::test]
    async fn get_host_interpolates_id() {
        let server = MockServer::start_async().await;
        let m = server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/fleet/hosts/abc-123");
                then.status(200).json_body(json!({"host_id": "abc-123"}));
            })
            .await;

        fleet(server.base_url())
            .get_host(Parameters(HostIdParams {
                host_id: "abc-123".to_string(),
            }))
            .await
            .unwrap();

        m.assert_async().await;
    }

    #[tokio::test]
    async fn query_events_builds_filters() {
        let server = MockServer::start_async().await;
        let m = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/v1/events")
                    .query_param("host_id", "H1")
                    .query_param("since", "2026-05-01T00:00:00Z")
                    .query_param("limit", "50")
                    .query_param("cursor", "abc-cursor");
                then.status(200)
                    .json_body(json!({"events": [], "next_cursor": null}));
            })
            .await;

        fleet(server.base_url())
            .query_events(Parameters(QueryEventsParams {
                host_id: vec!["H1".to_string()],
                since: Some("2026-05-01T00:00:00Z".to_string()),
                limit: Some(50),
                cursor: Some("abc-cursor".to_string()),
            }))
            .await
            .unwrap();

        m.assert_async().await;
    }

    #[tokio::test]
    async fn query_events_joins_multiple_host_ids_into_one_comma_param() {
        // #73: multiple host_ids must go out as a single comma-separated value,
        // not repeated params — the server reads it like its other multi-value
        // filters, and repeated params broke its deserializer.
        let server = MockServer::start_async().await;
        let m = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/v1/events")
                    .query_param("host_id", "H1,H2");
                then.status(200)
                    .json_body(json!({"events": [], "next_cursor": null}));
            })
            .await;

        fleet(server.base_url())
            .query_events(Parameters(QueryEventsParams {
                host_id: vec!["H1".to_string(), "H2".to_string()],
                since: None,
                limit: None,
                cursor: None,
            }))
            .await
            .unwrap();

        m.assert_async().await;
    }

    #[tokio::test]
    async fn auth_failure_surfaces_as_mcp_error() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/fleet/risk");
                then.status(401);
            })
            .await;
        let err = fleet(server.base_url()).fleet_risk().await.unwrap_err();
        // Auth maps to internal_error; the Display string contains "authentication".
        assert!(format!("{err:?}").to_lowercase().contains("auth"));
    }
}
