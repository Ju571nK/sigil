mod config;
mod local;
mod local_tools;
mod tools;
mod upstream;

use crate::config::Mode;
use crate::local::LocalUpstream;
use crate::local_tools::SigilLocal;
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

    match Mode::from_env()? {
        Mode::Fleet(cfg) => {
            tracing::info!(mode = "fleet", base_url = %cfg.base_url, mtls = cfg.mtls.is_some(), "starting sigil-mcp");
            let up = Arc::new(Upstream::new(&cfg)?);
            SigilFleet::new(up).serve(stdio()).await?.waiting().await?;
        }
        Mode::Local(cfg) => {
            tracing::info!(mode = "local", socket = %cfg.socket.display(), "starting sigil-mcp");
            let up = Arc::new(LocalUpstream::from_cfg(&cfg));
            SigilLocal::new(up).serve(stdio()).await?.waiting().await?;
        }
    }
    Ok(())
}
