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

    /// Override the control IPC socket path (Unix). Default: `/var/run/sigil/control.sock`
    /// as root, else `$XDG_RUNTIME_DIR/sigil/control.sock`. Lets a non-root / macOS
    /// agent expose the control plane (apply_policy, `sigil show stats`) without sudo.
    #[arg(long, global = true)]
    pub control_socket: Option<PathBuf>,

    /// Override the policy-signing keystore path. Default: `/etc/sigil/...` as root,
    /// else `$XDG_CONFIG_HOME/sigil/...` (Unix) or `%LOCALAPPDATA%\Sigil\...` (Windows).
    #[arg(long, global = true)]
    pub keystore: Option<PathBuf>,

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
    Doctor {
        /// Verify this binary's blake3 against a signed build manifest, then exit.
        #[arg(long)]
        verify_self: bool,
        /// Path to the signed build manifest JSON (required with --verify-self).
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
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
    /// Evaluate a proposed command or MCP server definition against the
    /// host's loaded policy (cold-disk). Prints a JSON verdict and exits with
    /// 0 (allow), 2 (deny/warn-fail), or 1 (usage/policy-load error).
    #[cfg(feature = "operator-cli")]
    Assess {
        /// The command to evaluate. For faithful deny-rule parity with the hook,
        /// pass the FULL command line here (e.g. `--command "rm -rf /tmp"`).
        /// `--arg` is a convenience for structural scanning; splitting may re-join
        /// with different spacing than the agent's original command line.
        #[arg(long)]
        command: Option<String>,
        /// Arguments to the command. Repeat for multiple args.
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
        /// Path to a JSON file containing an MCP server definition object.
        #[arg(long, conflicts_with = "mcp_stdin")]
        mcp_config: Option<std::path::PathBuf>,
        /// Read the MCP server definition JSON from stdin.
        #[arg(long, conflicts_with = "mcp_config")]
        mcp_stdin: bool,
        /// Server name (required with --mcp-config or --mcp-stdin).
        #[arg(long)]
        mcp_name: Option<String>,
        /// Treat a Warn verdict as exit 2 instead of 0.
        #[arg(long)]
        fail_on_warn: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ShowWhat {
    /// Print the merged effective policy.
    Config,
    /// Print fully expanded watch paths.
    Paths,
    /// Query the running daemon for stats via control IPC.
    Stats,
    /// Print this host's stable host_id — the UUID persisted in state.db on the
    /// agent's first run, and the value the sender's `host_id` must match.
    HostId,
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
    /// Print the current AI Guard risk assessment for each tool. Queries the
    /// running daemon over the control socket.
    #[cfg(feature = "operator-cli")]
    Risk {
        /// Filter to a single tool (`claude-code` or `codex`).
        #[arg(long = "tool")]
        tool: Option<String>,
        /// Render as a tab-separated table instead of raw JSON.
        #[arg(long = "pretty")]
        pretty: bool,
    },
}

#[cfg(test)]
mod cli_tests {
    use super::Cli;
    use clap::Parser;
    use std::path::Path;

    #[test]
    fn parses_control_socket_and_keystore_overrides() {
        let cli = Cli::parse_from([
            "sigil",
            "--control-socket",
            "/tmp/c.sock",
            "--keystore",
            "/tmp/ks.pem",
            "run",
        ]);
        assert_eq!(
            cli.control_socket.as_deref(),
            Some(Path::new("/tmp/c.sock"))
        );
        assert_eq!(cli.keystore.as_deref(), Some(Path::new("/tmp/ks.pem")));
    }

    #[test]
    fn path_overrides_default_to_none() {
        let cli = Cli::parse_from(["sigil", "run"]);
        assert!(cli.control_socket.is_none());
        assert!(cli.keystore.is_none());
    }
}
