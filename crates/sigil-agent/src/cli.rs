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

    /// Use a polling watcher instead of the OS-native one (inotify / FSEvents /
    /// ReadDirectoryChangesW). Use this where native filesystem events are
    /// unreliable — e.g. NFS-mounted homes, `virtiofs`/`9p` shares, or
    /// bind-mounts inside VM-backed container engines (Docker Desktop, Rancher
    /// Desktop). Only affects `run`.
    #[arg(long, global = true)]
    pub poll: bool,
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
    /// Ask the running daemon to re-read the on-disk policy.yaml without going
    /// through `apply_policy`. Useful after a hand-edit.
    #[cfg(feature = "operator-cli")]
    Reload,
}

#[derive(Subcommand, Debug)]
pub enum ShowWhat {
    /// Print the merged effective policy.
    Config,
    /// Print fully expanded watch paths.
    Paths,
    /// Query the running daemon for stats via control IPC.
    Stats,
    /// Query the running daemon for the active policy version + envelope expiry.
    #[cfg(feature = "operator-cli")]
    PolicyStatus,
    /// List the active watch targets and their compiled glob patterns.
    #[cfg(feature = "operator-cli")]
    Targets,
    /// Tail the agent's JSONL events. Reads the latest segment from the events
    /// directory; pass --follow to watch for new lines (Ctrl-C to stop).
    #[cfg(feature = "operator-cli")]
    Events {
        /// Number of trailing lines to show before following (or to dump and
        /// exit when --follow is not set).
        #[arg(short = 'n', long = "tail", default_value_t = 20)]
        tail: usize,
        /// Continue printing new lines as they arrive (200ms polling, Ctrl-C to stop).
        #[arg(short = 'f', long = "follow")]
        follow: bool,
        /// Render each event as a one-line summary instead of raw JSON.
        #[arg(long = "pretty")]
        pretty: bool,
    },
}
