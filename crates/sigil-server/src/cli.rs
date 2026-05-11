//! clap CLI for `sigil-server`.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sigil-server",
    version,
    about = "Sigil OSS reference policy/event server"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the HTTP server.
    Serve {
        /// Path to server.yaml.
        #[arg(long, default_value = "/etc/sigil-server/server.yaml")]
        config: PathBuf,
    },
}
