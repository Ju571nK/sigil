//! Clap subcommands for the sigil-sender binary.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sigil-sender", version, about = "Sigil Phase 2 sender")]
pub struct Cli {
    /// Path to sender.yaml (defaults: /etc/sigil/sender.yaml on unix,
    /// %ProgramData%\Sigil\sender.yaml on Windows).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the sender process (data_task + control_task).
    Start,
    /// Print health summary (cert status, last ack, lag) and exit.
    Doctor,
    /// Read config + cert, attempt one POST to a configured mock URL,
    /// print outcome, exit. Does NOT advance any offset on disk.
    DryRun {
        /// URL to POST a synthetic empty batch to (for cert/connectivity check).
        #[arg(long)]
        url: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_start() {
        let cli = Cli::try_parse_from(["sigil-sender", "start"]).unwrap();
        assert!(matches!(cli.command, Command::Start));
    }

    #[test]
    fn parses_doctor_with_global_config() {
        let cli =
            Cli::try_parse_from(["sigil-sender", "--config", "/tmp/s.yaml", "doctor"]).unwrap();
        assert_eq!(
            cli.config.as_deref().map(|p| p.to_str().unwrap()),
            Some("/tmp/s.yaml")
        );
        assert!(matches!(cli.command, Command::Doctor));
    }

    #[test]
    fn parses_dry_run_with_url() {
        let cli =
            Cli::try_parse_from(["sigil-sender", "dry-run", "--url", "https://localhost:9443"])
                .unwrap();
        match cli.command {
            Command::DryRun { url } => assert_eq!(url, "https://localhost:9443"),
            other => panic!("expected DryRun, got {other:?}"),
        }
    }
}
