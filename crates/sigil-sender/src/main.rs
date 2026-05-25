use anyhow::Result;
use clap::Parser;
use sigil_sender::cli::{Cli, Command};
use sigil_sender::config::SenderConfig;
use sigil_sender::runtime::{run, RuntimeCtx};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// Resolve the sender's host_id. Precedence: SIGIL_HOST_ID env (override) >
/// config `host_id` > error. Empty/whitespace is treated as unset.
fn resolve_host_id(env: Option<String>, cfg: Option<&str>) -> anyhow::Result<String> {
    let pick = |s: &str| {
        let t = s.trim();
        if t.is_empty() { None } else { Some(t.to_string()) }
    };
    if let Some(v) = env.as_deref().and_then(pick) {
        return Ok(v);
    }
    if let Some(v) = cfg.and_then(pick) {
        return Ok(v);
    }
    anyhow::bail!(
        "sender host_id not configured: set `host_id:` in sender.yaml (or the \
         SIGIL_HOST_ID env var). It must equal the agent's host_id (the agent's \
         state.db UUID); the server rejects events whose host_id does not match."
    )
}

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
            let host_id = resolve_host_id(std::env::var("SIGIL_HOST_ID").ok(), cfg.host_id.as_deref())?;
            let cancel = CancellationToken::new();
            let cancel_c = cancel.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                cancel_c.cancel();
            });
            run(RuntimeCtx {
                config: cfg,
                host_id,
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                sender_version: env!("CARGO_PKG_VERSION").to_string(),
                shutdown: cancel,
            })
            .await?;
        }
        Command::Doctor => {
            let cfg = SenderConfig::load(&config_path)?;
            println!("Sigil sender doctor");
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

#[cfg(test)]
mod tests {
    use super::resolve_host_id;

    #[test]
    fn env_wins_over_cfg() {
        let result = resolve_host_id(Some("env-id".into()), Some("cfg-id")).unwrap();
        assert_eq!(result, "env-id");
    }

    #[test]
    fn cfg_used_when_env_unset() {
        let result = resolve_host_id(None, Some("cfg-id")).unwrap();
        assert_eq!(result, "cfg-id");
    }

    #[test]
    fn both_unset_returns_err() {
        let result = resolve_host_id(None, None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("host_id not configured"));
    }

    #[test]
    fn empty_env_falls_through_to_cfg() {
        let result = resolve_host_id(Some("   ".into()), Some("cfg-id")).unwrap();
        assert_eq!(result, "cfg-id");
    }

    #[test]
    fn empty_env_and_empty_cfg_returns_err() {
        let result = resolve_host_id(Some("".into()), Some("  "));
        assert!(result.is_err());
    }
}
