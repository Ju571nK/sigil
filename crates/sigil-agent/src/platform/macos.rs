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

fn parse_uname_r(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn parse_route_n_get_default(s: &str) -> Option<String> {
    for line in s.lines() {
        if let Some(rest) = line.trim().strip_prefix("gateway:") {
            let g = rest.trim();
            if !g.is_empty() {
                return Some(g.to_string());
            }
        }
    }
    None
}

fn parse_scutil_dns(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if let Some(idx) = line.find("nameserver[") {
            let after = &line[idx..];
            if let Some(colon) = after.find(':') {
                let val = after[colon + 1..].trim();
                if !val.is_empty() && !out.contains(&val.to_string()) {
                    out.push(val.to_string());
                }
            }
        }
    }
    out
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

    fn kernel_version(&self) -> Option<String> {
        std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| parse_uname_r(&s))
    }

    fn default_gateway_v4(&self) -> Option<String> {
        std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| parse_route_n_get_default(&s))
    }

    fn default_gateway_v6(&self) -> Option<String> {
        std::process::Command::new("route")
            .args(["-n", "get", "-inet6", "default"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| parse_route_n_get_default(&s))
    }

    fn dns_servers(&self) -> Vec<String> {
        std::process::Command::new("scutil")
            .arg("--dns")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| parse_scutil_dns(&s))
            .unwrap_or_default()
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

    #[test]
    fn parse_route_n_get_default_extracts_gateway() {
        let fixture = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(
            parse_route_n_get_default(fixture),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn parse_route_n_get_default_returns_none_when_no_gateway_line() {
        let fixture = "route to: default\n   destination: default\n";
        assert_eq!(parse_route_n_get_default(fixture), None);
    }

    #[test]
    fn parse_scutil_dns_extracts_all_nameservers_dedup() {
        let fixture = "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : 1.1.1.1\n\nresolver #2\n  nameserver[0] : 192.168.1.1\n";
        let mut got = parse_scutil_dns(fixture);
        got.sort();
        assert_eq!(got, vec!["1.1.1.1", "192.168.1.1"]);
    }

    #[test]
    fn parse_scutil_dns_returns_empty_for_no_nameservers() {
        let fixture = "DNS configuration\nresolver #1\n";
        assert!(parse_scutil_dns(fixture).is_empty());
    }

    #[test]
    fn parse_uname_r_trims_trailing_newline() {
        assert_eq!(parse_uname_r("23.5.0\n"), Some("23.5.0".to_string()));
    }

    #[test]
    fn parse_uname_r_returns_none_for_empty() {
        assert_eq!(parse_uname_r("\n"), None);
        assert_eq!(parse_uname_r(""), None);
    }
}
