//! macOS platform: FDA probe, host_id, multi-user enumeration.

use super::{FdaState, Platform};
use sigil_core::host_id::HostIdResolver;
use sigil_core::policy::expand::{UserContext, UserEnumerator};
use std::path::Path;
use std::process::Command;
use uuid::Uuid;

pub struct MacosPlatform;

impl Default for MacosPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl MacosPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Platform for MacosPlatform {
    fn fda_state(&self) -> FdaState {
        // Probe a known FDA-protected system path.
        let probe = Path::new("/Library/Application Support/com.apple.TCC/TCC.db");
        match std::fs::metadata(probe) {
            Ok(_) => FdaState::Granted,
            Err(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => FdaState::Denied,
                std::io::ErrorKind::NotFound => FdaState::Unknown,
                _ => FdaState::Unknown,
            },
        }
    }
    fn name(&self) -> &'static str {
        "macos"
    }
}

impl HostIdResolver for MacosPlatform {
    fn machine_id(&self) -> Option<String> {
        // `system_profiler SPHardwareDataType` includes "Hardware UUID:".
        let out = Command::new("system_profiler")
            .args(["SPHardwareDataType"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if let Some((_, v)) = line.split_once("Hardware UUID:") {
                return Some(v.trim().to_string());
            }
        }
        None
    }
    fn hostname(&self) -> Option<String> {
        Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    }
    fn fresh_uuid(&self) -> String {
        Uuid::new_v4().to_string()
    }
}

impl UserEnumerator for MacosPlatform {
    fn list(&self) -> Vec<UserContext> {
        let mut out = Vec::new();
        let users_dir = Path::new("/Users");
        let Ok(entries) = std::fs::read_dir(users_dir) else {
            return out;
        };
        for ent in entries.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if name.starts_with('_') || name == "Shared" || name == "Guest" {
                continue;
            }
            let home = users_dir.join(&name);
            let uid_or_sid = ent
                .metadata()
                .ok()
                .map(|m| {
                    use std::os::unix::fs::MetadataExt;
                    m.uid().to_string()
                })
                .unwrap_or_else(|| "0".to_string());
            // Skip system accounts (UID < 500).
            if uid_or_sid.parse::<u32>().unwrap_or(0) < 500 {
                continue;
            }
            out.push(UserContext {
                name,
                home,
                uid_or_sid,
            });
        }
        out
    }
}

use super::hw_fingerprint::{pick_stable_mac, HardwareFingerprint, IfaceKind};

impl HardwareFingerprint for MacosPlatform {
    fn platform_uuid(&self) -> String {
        match Command::new("system_profiler")
            .args(["SPHardwareDataType"])
            .output()
        {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout);
                for line in s.lines() {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("Hardware UUID:") {
                        return rest.trim().to_string();
                    }
                }
                String::new()
            }
            _ => String::new(),
        }
    }

    fn stable_mac(&self) -> String {
        // MacAddressIterator yields MacAddress values with no name attached.
        // Use name_by_mac_address to resolve interface name for each entry.
        let ifaces: Vec<(String, [u8; 6])> = mac_address::MacAddressIterator::new()
            .map(|it| {
                it.filter_map(|m| {
                    let bytes = m.bytes();
                    let name = mac_address::name_by_mac_address(&m)
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    if name.is_empty() {
                        None
                    } else {
                        Some((name, bytes))
                    }
                })
                .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        pick_stable_mac(ifaces, |_| IfaceKind::Other)
    }

    fn cpu_brand(&self) -> String {
        match Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
        {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fda_probe_returns_three_state() {
        let p = MacosPlatform::new();
        let s = p.fda_state();
        assert!(matches!(
            s,
            FdaState::Granted | FdaState::Denied | FdaState::Unknown
        ));
    }

    #[test]
    fn enumerates_at_least_current_user() {
        let p = MacosPlatform::new();
        let users = p.list();
        // CI runners always have at least one user under /Users — typically 'runner'.
        assert!(!users.is_empty());
    }

    #[test]
    fn fresh_uuid_is_unique() {
        let p = MacosPlatform::new();
        let a = p.fresh_uuid();
        let b = p.fresh_uuid();
        assert_ne!(a, b);
    }
}
