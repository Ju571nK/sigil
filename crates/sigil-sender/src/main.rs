use sigil_sender::cli::{Cli, Command};
use sigil_sender::config::SenderConfig;
use sigil_sender::runtime::{run, RuntimeCtx};
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

fn default_config_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/sigil/sender.yaml")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\ProgramData\Sigil\sender.yaml")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(default_config_path);
    match cli.command {
        Command::Start => {
            // NOTE: control plane only today (policy poll + apply_policy IPC).
            // Data plane (read JSONL spool → POST /v1/events → ack) lands in
            // Plan B follow-up tickets B11.x; see crates/sigil-sender/src/runtime.rs.
            let cfg = SenderConfig::load(&config_path)?;
            let cancel = CancellationToken::new();
            let cancel_c = cancel.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                cancel_c.cancel();
            });
            run(RuntimeCtx {
                config: cfg,
                host_id: std::env::var("SIGIL_HOST_ID").unwrap_or_else(|_| "unknown".into()),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                sender_version: env!("CARGO_PKG_VERSION").to_string(),
                shutdown: cancel,
            })
            .await?;
        }
        Command::Doctor => {
            let cfg = SenderConfig::load(&config_path)?;
            println!("ANDEDA sender doctor");
            println!("[OK] config loaded: {}", config_path.display());
            println!("[OK] server_base_url: {}", cfg.server_base_url);
            println!("[OK] events_dir: {}", cfg.events_dir.display());
            println!("[OK] agent_control: {}", cfg.agent_control.display());
        }
        Command::DryRun { url } => {
            println!("dry-run url={url} (not yet wired)");
        }
    }
    Ok(())
}
