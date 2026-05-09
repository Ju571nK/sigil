//! ANDEDA agent — tokio runtime + system integration.

mod cli;
mod watcher;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Command::Run => {
            println!("(stub) andeda run");
        }
        cli::Command::Doctor => {
            println!("(stub) andeda doctor");
        }
        cli::Command::Show { what } => {
            println!("(stub) andeda show {:?}", what);
        }
        cli::Command::Version => {
            println!("andeda {}", env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}
