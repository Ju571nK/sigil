mod config;
mod tools;
mod upstream;

use crate::config::Config;
use crate::tools::SigilFleet;
use crate::upstream::Upstream;
use rmcp::transport::stdio;
use rmcp::ServiceExt;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // MCP speaks JSON-RPC over stdout; ALL logs MUST go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sigil_mcp=info".into()),
        )
        .init();

    let cfg = Config::from_env()?;
    tracing::info!(base_url = %cfg.base_url, mtls = cfg.mtls.is_some(), "starting sigil-mcp");
    let upstream = Arc::new(Upstream::new(&cfg)?);
    let service = SigilFleet::new(upstream).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
