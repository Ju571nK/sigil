//! Sigil agent — tokio runtime + system integration.

use clap::Parser;
use sigil_agent::control::{default_control_pipe_name, default_control_socket};
#[cfg(feature = "operator-cli")]
use sigil_agent::control_client;
use sigil_agent::{cli, doctor, runtime, show};

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Command::Run => {
            let cfg = runtime::RuntimeConfig {
                policy_path: cli.policy.clone(),
                state_db_path: cli.state_db.clone().unwrap_or_else(default_state_db_path),
                events_dir: cli.events_dir.clone().unwrap_or_else(default_events_dir),
                control_socket: cli
                    .control_socket
                    .clone()
                    .unwrap_or_else(default_control_socket),
                control_pipe_name: default_control_pipe_name(),
                poll_watcher: cli.poll,
                keystore_path: cli.keystore.clone(),
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(runtime::run(cfg))?;
            std::process::exit(code);
        }
        cli::Command::Doctor {
            verify_self,
            manifest,
        } => {
            let code = if verify_self {
                doctor::verify_self(manifest)
            } else {
                doctor::run(cli.policy)
            };
            std::process::exit(code);
        }
        cli::Command::Show { what } => {
            let code = show::run(
                what,
                cli.policy.clone(),
                cli.events_dir.clone(),
                cli.state_db.clone().unwrap_or_else(default_state_db_path),
            )?;
            std::process::exit(code);
        }
        cli::Command::Version => {
            println!("sigil {}", env!("CARGO_PKG_VERSION"));
        }
        #[cfg(feature = "operator-cli")]
        cli::Command::Reload => {
            let code = reload();
            std::process::exit(code);
        }
    }
    Ok(())
}

#[cfg(feature = "operator-cli")]
fn reload() -> i32 {
    match control_client::query(&sigil_agent::control::Request::ReloadPolicy) {
        Ok(resp) if resp.ok => {
            println!("reload requested — check `journalctl -u sigil` for the result");
            0
        }
        Ok(resp) => {
            eprintln!(
                "sigil reload: daemon refused the request{}",
                resp.error.map(|e| format!(": {e}")).unwrap_or_default()
            );
            1
        }
        Err(e) => {
            eprintln!("sigil reload: {e}");
            1
        }
    }
}

fn default_state_db_path() -> std::path::PathBuf {
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        "/var/lib/sigil/state.db".into()
    } else {
        std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap_or_default())
            .join("Sigil")
            .join("state.db")
    }
}

fn default_events_dir() -> std::path::PathBuf {
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        "/var/log/sigil".into()
    } else {
        std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap_or_default())
            .join("Sigil")
            .join("events")
    }
}
