//! Sigil agent — tokio runtime + system integration.

use clap::Parser;
use sigil_agent::{cli, doctor, runtime, show};

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Command::Run => {
            let cfg = runtime::RuntimeConfig {
                policy_path: cli.policy.clone(),
                state_db_path: cli.state_db.clone().unwrap_or_else(default_state_db_path),
                events_dir: cli.events_dir.clone().unwrap_or_else(default_events_dir),
                control_socket: default_control_socket(),
                control_pipe_name: default_control_pipe_name(),
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(runtime::run(cfg))?;
            std::process::exit(code);
        }
        cli::Command::Doctor => {
            let code = doctor::run(cli.policy);
            std::process::exit(code);
        }
        cli::Command::Show { what } => {
            let code = show::run(what, cli.policy)?;
            std::process::exit(code);
        }
        cli::Command::Version => {
            println!("sigil {}", env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}

fn default_state_db_path() -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        "/var/lib/sigil/state.db".into()
    } else {
        std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap_or_default())
            .join("Sigil/state.db")
    }
}

fn default_events_dir() -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        "/var/log/sigil".into()
    } else {
        std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap_or_default())
            .join("Sigil/events")
    }
}

fn default_control_socket() -> std::path::PathBuf {
    "/var/run/sigil/control.sock".into()
}

fn default_control_pipe_name() -> String {
    r"\\.\pipe\sigil-control".to_string()
}
