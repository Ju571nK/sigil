mod config;
mod local;
mod local_tools;
mod print_config;
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

/// Handle `--version` / `-V` before any server setup (#161): a bare invocation
/// starts the MCP server, so the version flag must be intercepted explicitly or
/// it would silently launch the server instead of printing a version.
fn handle_version() -> Option<i32> {
    match std::env::args().nth(1).as_deref() {
        Some("--version") | Some("-V") => {
            println!("sigil-mcp {}", env!("CARGO_PKG_VERSION"));
            Some(0)
        }
        _ => None,
    }
}

/// Handle `--print-config [client]` before any async/server setup. Returns
/// `Some(exit_code)` when the flag was handled (the caller then exits), else
/// `None` to start the server as usual.
fn handle_print_config() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("--print-config") {
        return None;
    }
    let client = args.next();
    // Pin the absolute path of THIS binary so the emitted config works even when
    // the MCP client doesn't see the user's interactive-shell PATH (#72).
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "sigil-mcp".to_string());
    match print_config::render_config(&exe, client.as_deref()) {
        Ok(block) => {
            print!("{block}");
            Some(0)
        }
        Err(msg) => {
            eprintln!("sigil-mcp --print-config: {msg}");
            Some(2)
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Some(code) = handle_version() {
        std::process::exit(code);
    }
    if let Some(code) = handle_print_config() {
        std::process::exit(code);
    }
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
