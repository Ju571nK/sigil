//! ANDEDA agent — tokio runtime + system integration.

mod cli;
mod control;
mod debouncer;
mod doctor;
mod hasher;
mod normalizer;
mod platform;
mod show;
mod sink_task;
mod state_task;
mod watcher;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Command::Run => {
            println!("(stub) andeda run");
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
            println!("andeda {}", env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}
