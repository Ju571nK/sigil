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
    /// #184 — issue a single-use, per-host enrollment token. Prints the
    /// plaintext token ONCE to stdout; only its blake3 hash is stored in the
    /// configured `enroll_tokens_path`. Requires enrollment to be configured.
    EnrollToken {
        /// Path to server.yaml (for `enroll_tokens_path`).
        #[arg(long, default_value = "/etc/sigil-server/server.yaml")]
        config: PathBuf,
        /// Target host UUID this token is bound to.
        #[arg(long)]
        host_id: String,
        /// Time-to-live, e.g. `1h`, `30m`, `2h`. Default `1h`.
        #[arg(long, default_value = "1h")]
        ttl: String,
    },
}
