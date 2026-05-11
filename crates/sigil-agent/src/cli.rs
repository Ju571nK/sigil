//! clap CLI definitions.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sigil",
    version,
    about = "AI-Native Detection Engine for Device Assurance"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Override the policy file path.
    #[arg(long, global = true)]
    pub policy: Option<PathBuf>,

    /// Override the state.db path.
    #[arg(long, global = true)]
    pub state_db: Option<PathBuf>,

    /// Override the events directory.
    #[arg(long, global = true)]
    pub events_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run as a daemon.
    Run,
    /// Diagnose configuration and permissions; do not start the daemon.
    Doctor,
    /// Inspect static or live state.
    Show {
        #[command(subcommand)]
        what: ShowWhat,
    },
    /// Print the version (also available via `--version`).
    Version,
}

#[derive(Subcommand, Debug)]
pub enum ShowWhat {
    /// Print the merged effective policy.
    Config,
    /// Print fully expanded watch paths.
    Paths,
    /// Query the running daemon for stats via control IPC.
    Stats,
}
