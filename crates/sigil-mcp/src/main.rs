use rmcp::{
    handler::server::router::tool::ToolRouter,
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};

#[derive(Clone)]
pub struct SigilFleet {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl SigilFleet {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Liveness ping; returns \"pong\".")]
    async fn ping(&self) -> String {
        "pong".to_string()
    }
}

impl Default for SigilFleet {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
impl ServerHandler for SigilFleet {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // MCP speaks JSON-RPC over stdout; ALL logs MUST go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let service = SigilFleet::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ping_returns_pong() {
        let fleet = SigilFleet::new();
        let result = fleet.ping().await;
        assert_eq!(result, "pong");
    }
}
