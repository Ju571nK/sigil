//! clap CLI surface for `sigil-sign`.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sigil-sign",
    version,
    about = "Sign / verify / inspect Sigil policy bundles"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a fresh ed25519 signing keypair.
    Keygen {
        /// Identifier the agent's keystore will use to look this key up.
        /// Stamped into every signed envelope's `signing_pubkey_id`.
        #[arg(long)]
        id: String,
        /// Output path for the keypair JSON file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Wrap a YAML policy in a signed envelope.
    Sign {
        /// Path to the YAML policy file (the bytes that get signed).
        #[arg(long, value_name = "PATH")]
        r#in: PathBuf,
        /// Path to the signing keypair JSON (output of `keygen`).
        #[arg(long)]
        key: PathBuf,
        /// Monotonic policy version (must increase across signings for the
        /// same fleet — agent rejects regressions).
        #[arg(long)]
        policy_version: i64,
        /// RFC 3339 timestamp after which the agent treats the envelope as
        /// expired. Recommend 1 month for routine signings, 1 day for rotations.
        #[arg(long)]
        valid_until: String,
        /// Output path for the signed `SignedPolicyResponse` JSON.
        #[arg(long)]
        out: PathBuf,
    },
    /// Run the host-side `verify_envelope` 5-check chain locally.
    Verify {
        /// Path to a signed envelope JSON (output of `sign`).
        #[arg(long, value_name = "PATH")]
        r#in: PathBuf,
        /// Path to the agent's `policy-signing-pubkeys.pem` keystore.
        #[arg(long)]
        keystore: PathBuf,
        /// Override "now" for the active-window check. RFC 3339. Default = system time.
        #[arg(long)]
        now: Option<String>,
        /// Pretend the agent's `last_applied_policy_version` is this value
        /// (drives the version-regression check). Default = 0.
        #[arg(long, default_value_t = 0)]
        last_applied: i64,
    },
    /// Pretty-print a signed envelope's metadata (no signature check).
    Inspect {
        /// Path to a signed envelope JSON.
        #[arg(long, value_name = "PATH")]
        r#in: PathBuf,
    },
    /// Sign a license document into a SignedLicense bundle (vendor key required).
    License {
        /// Path to the vendor signing keypair JSON (output of `keygen`).
        #[arg(long)]
        key: PathBuf,
        /// Customer identifier (e.g. ACME).
        #[arg(long)]
        customer_id: String,
        /// Maximum licensed active hosts.
        #[arg(long)]
        max_hosts: u32,
        /// Days from now until the license expires (not_after = now + valid_days).
        #[arg(long)]
        valid_days: u32,
        /// Output path for the SignedLicense JSON bundle.
        #[arg(long)]
        out: PathBuf,
        /// Optional explicit license id; auto-generated (SIGIL-<year>-<CUST>-<rand6>) if omitted.
        #[arg(long)]
        license_id: Option<String>,
    },
    /// Verify a signed audit-log chain file (hash-chain + optional signatures).
    VerifyAudit {
        /// Path to the audit chain file (license-audit.jsonl).
        #[arg(long, value_name = "PATH")]
        r#in: PathBuf,
        /// Externally-observed audit pubkey ("ed25519:<b64>"). Omit to check chain structure only.
        #[arg(long)]
        pubkey: Option<String>,
        /// Expected head hash (from /v1/meta audit_head.hash) to assert against.
        #[arg(long)]
        expect_head: Option<String>,
    },
}
