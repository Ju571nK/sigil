//! Windows platform: host_id, multi-user enumeration. FDA n/a.

use super::{FdaState, Platform};
use andeda_core::host_id::HostIdResolver;
use andeda_core::policy::expand::{UserContext, UserEnumerator};
use std::path::Path;
use std::process::Command;
use uuid::Uuid;

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Platform for WindowsPlatform {
    fn fda_state(&self) -> FdaState {
        FdaState::Granted
    }
    fn name(&self) -> &'static str {
        "windows"
    }
}

impl HostIdResolver for WindowsPlatform {
    fn machine_id(&self) -> Option<String> {
        // `reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid`
        let out = Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("MachineGuid") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(v) = parts.last() {
                    return Some(v.to_string());
                }
            }
        }
        None
    }
    fn hostname(&self) -> Option<String> {
        std::env::var("COMPUTERNAME").ok()
    }
    fn fresh_uuid(&self) -> String {
        Uuid::new_v4().to_string()
    }
}

impl UserEnumerator for WindowsPlatform {
    fn list(&self) -> Vec<UserContext> {
        let mut out = Vec::new();
        let users_dir = Path::new(r"C:\Users");
        let Ok(entries) = std::fs::read_dir(users_dir) else {
            return out;
        };
        for ent in entries.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            // Skip well-known non-human profiles.
            if matches!(
                name.as_str(),
                "Default" | "Default User" | "Public" | "All Users"
            ) {
                continue;
            }
            // Skip directories starting with `.` or known service accounts.
            if name.starts_with('.') {
                continue;
            }
            let home = users_dir.join(&name);
            // Use the directory name as a stable per-user identifier; Phase 1 does
            // not call NetUserEnum to convert to SID (avoids extra deps).
            out.push(UserContext {
                name: name.clone(),
                home,
                uid_or_sid: format!("name:{name}"),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fda_state_is_granted() {
        let p = WindowsPlatform::new();
        assert_eq!(p.fda_state(), FdaState::Granted);
    }

    #[test]
    fn enumerates_users() {
        let p = WindowsPlatform::new();
        let _users = p.list();
        // CI runners typically have at least 'runneradmin' or 'Administrator'.
    }

    #[test]
    fn fresh_uuid_is_unique() {
        let p = WindowsPlatform::new();
        let a = p.fresh_uuid();
        let b = p.fresh_uuid();
        assert_ne!(a, b);
    }
}
