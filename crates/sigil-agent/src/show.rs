//! `sigil show ...` — print effective config, expanded paths, or live stats.

use crate::cli::ShowWhat;
use crate::platform::ActivePlatform;
use sigil_core::policy::expand::{expand_per_user, EnvLookup};
use sigil_core::policy::{current_platform, defaults, merge};
use std::path::PathBuf;

pub fn run(what: ShowWhat, policy_override: Option<PathBuf>) -> anyhow::Result<i32> {
    let user_doc = match policy_override.as_ref() {
        Some(p) => Some(sigil_core::policy::parse(&std::fs::read_to_string(p)?)?),
        None => None,
    };
    let effective = merge(defaults()?, user_doc, current_platform())?;

    match what {
        ShowWhat::Config => {
            println!("{}", serde_yaml::to_string(&effective.targets)?);
        }
        ShowWhat::Paths => {
            let plat = ActivePlatform::new();
            let users = sigil_core::policy::expand::UserEnumerator::list(&plat);
            let env = EnvLookup;
            for t in &effective.targets {
                println!("# {} ({:?})", t.id, t.tier);
                for path_template in &t.paths {
                    for r in expand_per_user(path_template, &users, &env) {
                        match r {
                            Ok(p) => println!("  {}", p.display()),
                            Err(e) => println!("  ! expand error: {e}"),
                        }
                    }
                }
            }
        }
        ShowWhat::Stats => {
            println!("(Phase 1: stats over IPC implemented in a later task; for now, run `sigil run` and read the next heartbeat from the JSONL.)");
        }
    }
    Ok(0)
}
