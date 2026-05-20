use anyhow::{Context, Result};
use clap::Parser;
use sigil_signer::cli::{Cli, Command};
use sigil_signer::{inspect, keygen, license, sign, verify};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn parse_rfc3339(s: &str, what: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).with_context(|| format!("parse {what} as RFC 3339: {s}"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { id, out } => {
            let f = keygen::keygen(&id, &out)?;
            println!("wrote keypair {} (id={})", out.display(), f.id);
            println!("ed25519_pubkey_b64: {}", f.ed25519_pubkey_b64);
            println!("Add this pubkey to the agent's policy-signing-pubkeys.pem keystore.");
        }
        Command::Sign {
            r#in,
            key,
            policy_version,
            valid_until,
            out,
        } => {
            let key_file = keygen::SigningKeyFile::load(&key)?;
            let valid_until = parse_rfc3339(&valid_until, "valid_until")?;
            let resp = sign::sign_to_file(
                sign::SignArgs {
                    yaml_path: &r#in,
                    key_file: &key_file,
                    policy_version,
                    valid_until,
                    now: OffsetDateTime::now_utc(),
                },
                &out,
            )?;
            println!(
                "signed policy_version={} → {}",
                policy_version,
                out.display()
            );
            println!("etag: {}", resp.etag);
        }
        Command::Verify {
            r#in,
            keystore,
            now,
            last_applied,
        } => {
            let now = match now {
                Some(s) => parse_rfc3339(&s, "now")?,
                None => OffsetDateTime::now_utc(),
            };
            let result = verify::verify_file(&r#in, &keystore, now, last_applied)?;
            match result {
                Ok(v) => {
                    println!(
                        "OK: pubkey_id={} policy_version={}",
                        v.signing_pubkey_id, v.policy_version
                    );
                }
                Err(e) => {
                    eprintln!("FAIL: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Inspect { r#in } => {
            let r = inspect::inspect_file(&r#in)?;
            inspect::print_report(&r);
        }
        Command::License {
            key,
            customer_id,
            max_hosts,
            valid_days,
            out,
            license_id,
        } => {
            let key_file = keygen::SigningKeyFile::load(&key)?;
            let signed = license::sign_to_file(
                license::LicenseArgs {
                    key_file: &key_file,
                    customer_id,
                    max_hosts,
                    valid_days,
                    license_id,
                    now: OffsetDateTime::now_utc(),
                },
                &out,
            )?;
            println!("signed license → {}", out.display());
            println!("  license_id:        {}", signed.license.license_id);
            println!("  customer_id:       {}", signed.license.customer_id);
            println!("  max_hosts:         {}", signed.license.max_hosts);
            println!(
                "  not_after:         {}",
                signed
                    .license
                    .not_after
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap()
            );
            println!("  signing_pubkey_id: {}", signed.signing_pubkey_id);
        }
    }
    Ok(())
}
