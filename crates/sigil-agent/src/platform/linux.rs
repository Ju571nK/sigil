//! Linux platform: host_id, multi-user enumeration via `/etc/passwd`,
//! hardware fingerprint via `/etc/machine-id` + `/proc/cpuinfo`.
//!
//! Status: minimal foundation (Phase 3a). The file watcher itself is the
//! `notify` crate's inotify backend, which is platform-agnostic from the
//! agent's point of view. Items marked `TODO(community)` below are good
//! first contributions — see CONTRIBUTING.md.
//!
//! `TODO(community)`: inotify watch-count limit handling. When a recursive
//! watch tree exceeds `/proc/sys/fs/inotify/max_user_watches`, `notify`
//! surfaces an `ENOSPC` error per failed subdir. Today those are logged by
//! the watcher; a richer treatment would emit a posture event ("coverage
//! degraded — N subtrees not watched") and have `doctor` warn when the sysctl
//! looks low relative to the policy's path count.
//!
//! `TODO(community)`: `fda_state()` is `Granted` unconditionally (Linux has
//! no Full-Disk-Access gate — coverage is just file permissions). A more
//! informative implementation could reflect whether the daemon runs as root
//! / with `CAP_DAC_READ_SEARCH` vs. a limited user, and surface that in
//! `doctor`.
//!
//! `TODO(community)`: `list()` parses `/etc/passwd` directly. On hosts joined
//! to LDAP / Active Directory, real users may only be visible via
//! `getent passwd`. Adding an opt-in `getent` path (config-gated, since AD
//! homes are often NFS-mounted and slow) would broaden coverage.

use super::{FdaState, Platform};
use sigil_core::host_id::HostIdResolver;
use sigil_core::policy::expand::{UserContext, UserEnumerator};
use std::path::PathBuf;
use uuid::Uuid;

pub struct LinuxPlatform;

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Platform for LinuxPlatform {
    fn fda_state(&self) -> FdaState {
        // Linux has no TCC / Full Disk Access concept; what the agent can see
        // is governed purely by file permissions and how it is launched.
        FdaState::Granted
    }
    fn name(&self) -> &'static str {
        "linux"
    }

    fn kernel_version(&self) -> Option<String> {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|s| parse_osrelease(&s))
    }

    fn default_gateway_v4(&self) -> Option<String> {
        std::fs::read_to_string("/proc/net/route")
            .ok()
            .and_then(|s| parse_proc_net_route_v4(&s))
    }

    fn default_gateway_v6(&self) -> Option<String> {
        let out = std::process::Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        for line in s.lines() {
            let mut iter = line.split_whitespace();
            if iter.next() == Some("default") && iter.next() == Some("via") {
                if let Some(gw) = iter.next() {
                    return Some(gw.to_string());
                }
            }
        }
        None
    }

    fn dns_servers(&self) -> Vec<String> {
        std::fs::read_to_string("/etc/resolv.conf")
            .ok()
            .map(|s| parse_resolv_conf(&s))
            .unwrap_or_default()
    }
}

impl HostIdResolver for LinuxPlatform {
    fn machine_id(&self) -> Option<String> {
        read_machine_id()
    }
    fn hostname(&self) -> Option<String> {
        // /etc/hostname is the canonical static hostname; fall back to $HOSTNAME.
        let from_file = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        from_file.or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
    }
    fn fresh_uuid(&self) -> String {
        Uuid::new_v4().to_string()
    }
}

impl UserEnumerator for LinuxPlatform {
    fn list(&self) -> Vec<UserContext> {
        let Ok(text) = std::fs::read_to_string("/etc/passwd") else {
            return Vec::new();
        };
        text.lines().filter_map(parse_passwd_line).collect()
    }
}

use super::hw_fingerprint::{pick_stable_mac, HardwareFingerprint, IfaceKind};

impl HardwareFingerprint for LinuxPlatform {
    fn platform_uuid(&self) -> String {
        read_machine_id().unwrap_or_default()
    }

    fn stable_mac(&self) -> String {
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
        // Linux interface names: `eth0` / `enp3s0` / `ens5` → Ethernet;
        // `wlan0` / `wlp2s0` → Wi-Fi. The exclusion list in hw_fingerprint
        // already drops `lo`, `docker*`, `veth*`, `br-*`, `virbr*`, `tun*`, `tap*`.
        pick_stable_mac(ifaces, |name| {
            let lc = name.to_lowercase();
            if lc.starts_with("eth") || lc.starts_with("en") {
                IfaceKind::Ethernet
            } else if lc.starts_with("wlan") || lc.starts_with("wl") {
                IfaceKind::WiFi
            } else {
                IfaceKind::Other
            }
        })
    }

    fn cpu_brand(&self) -> String {
        cpu_brand_from_cpuinfo(&std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default())
    }
}

/// Read `/etc/machine-id`, falling back to the older D-Bus location. Returns
/// `None` if neither exists or is empty (e.g. minimal containers) — the
/// caller then uses a persisted UUID host_id instead.
fn read_machine_id() -> Option<String> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Extract the CPU brand from `/proc/cpuinfo` contents (the first `model name`
/// line). Pure so it can be unit-tested without reading the host's file. Note:
/// on ARM Linux there is often no `model name` line — returns empty there.
fn cpu_brand_from_cpuinfo(contents: &str) -> String {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            if let Some(idx) = rest.find(':') {
                return rest[idx + 1..].trim().to_string();
            }
        }
    }
    String::new()
}

/// Parse one `/etc/passwd` line into a `UserContext`, or `None` if it is a
/// system / service account, a malformed line, or has no real home directory.
///
/// Format: `name:passwd:uid:gid:gecos:home:shell` (7 colon-separated fields).
/// Keep entries with UID in `[1000, 65534)` (the conventional human range on
/// modern distros; 65534 is `nobody`) that have a non-trivial home.
fn parse_passwd_line(line: &str) -> Option<UserContext> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // NIS compat entries (`+`, `-`, `+@netgroup`) — skip.
    if line.starts_with('+') || line.starts_with('-') {
        return None;
    }
    let fields: Vec<&str> = line.split(':').collect();
    if fields.len() < 7 {
        return None;
    }
    let name = fields[0];
    let uid: u32 = fields[2].parse().ok()?;
    let home = fields[5];
    if name.is_empty() || name == "nobody" {
        return None;
    }
    if !(1000..65534).contains(&uid) {
        return None;
    }
    if home.is_empty() || home == "/" || home == "/nonexistent" || home == "/dev/null" {
        return None;
    }
    Some(UserContext {
        name: name.to_string(),
        home: PathBuf::from(home),
        uid_or_sid: uid.to_string(),
    })
}

fn parse_osrelease(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

fn parse_resolv_conf(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("nameserver") {
            let val = rest.trim();
            if !val.is_empty() && !out.iter().any(|x: &String| x == val) {
                out.push(val.to_string());
            }
        }
    }
    out
}

fn parse_proc_net_route_v4(s: &str) -> Option<String> {
    for (i, line) in s.lines().enumerate() {
        if i == 0 { continue; } // header
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 { continue; }
        let destination = cols[1];
        let gateway_hex = cols[2];
        if destination == "00000000" {
            return hex_le_to_ipv4(gateway_hex);
        }
    }
    None
}

fn hex_le_to_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 { return None; }
    let v = u32::from_str_radix(hex, 16).ok()?;
    let b0 = (v & 0xff) as u8;
    let b1 = ((v >> 8) & 0xff) as u8;
    let b2 = ((v >> 16) & 0xff) as u8;
    let b3 = ((v >> 24) & 0xff) as u8;
    Some(format!("{}.{}.{}.{}", b0, b1, b2, b3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fda_state_is_granted() {
        assert_eq!(LinuxPlatform::new().fda_state(), FdaState::Granted);
    }

    #[test]
    fn name_is_linux() {
        assert_eq!(LinuxPlatform::new().name(), "linux");
    }

    #[test]
    fn fresh_uuid_is_unique() {
        let p = LinuxPlatform::new();
        assert_ne!(p.fresh_uuid(), p.fresh_uuid());
    }

    #[test]
    fn enumerates_users_from_real_passwd() {
        // Whatever this box's /etc/passwd holds — a dev machine or a hosted CI
        // VM has human users, a minimal container often has none — list() must
        // not panic, and every entry it does return must look like a real human
        // account. (The parsing itself is covered by parse_passwd_* below.)
        let users = LinuxPlatform::new().list();
        for u in &users {
            assert!(u.home.starts_with("/"));
            assert!(u.uid_or_sid.parse::<u32>().unwrap() >= 1000);
        }
    }

    #[test]
    fn machine_id_does_not_panic() {
        // May be None inside minimal containers — just must not panic.
        let _ = LinuxPlatform::new().machine_id();
    }

    #[test]
    fn cpu_brand_on_host_is_some_string() {
        // x86_64 Linux (incl. GitHub runners) has `model name` in /proc/cpuinfo;
        // ARM may not. Either way it must be a String, not a panic.
        let _ = LinuxPlatform::new().cpu_brand();
    }

    #[test]
    fn parse_passwd_keeps_human_users() {
        let u = parse_passwd_line("alice:x:1001:1001:Alice:/home/alice:/bin/bash").unwrap();
        assert_eq!(u.name, "alice");
        assert_eq!(u.home, PathBuf::from("/home/alice"));
        assert_eq!(u.uid_or_sid, "1001");
    }

    #[test]
    fn parse_passwd_skips_system_and_service_accounts() {
        assert!(parse_passwd_line("root:x:0:0:root:/root:/bin/bash").is_none());
        assert!(parse_passwd_line("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin").is_none());
        assert!(
            parse_passwd_line("www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin").is_none()
        );
        assert!(
            parse_passwd_line("nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin")
                .is_none()
        );
        // Service-ish account inside the human UID range but with no real home.
        assert!(parse_passwd_line("svc:x:1500:1500::/nonexistent:/usr/sbin/nologin").is_none());
        // NIS compat / comments / malformed.
        assert!(parse_passwd_line("+::::::").is_none());
        assert!(parse_passwd_line("# comment").is_none());
        assert!(parse_passwd_line("garbage").is_none());
        assert!(parse_passwd_line("a:b:notanumber:d:e:f:g").is_none());
    }

    #[test]
    fn cpu_brand_parses_model_name_line() {
        let cpuinfo = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU\nstepping\t: 7\n";
        assert_eq!(cpu_brand_from_cpuinfo(cpuinfo), "Intel(R) Xeon(R) CPU");
        assert_eq!(cpu_brand_from_cpuinfo("processor\t: 0\n"), "");
    }

    #[test]
    fn parse_resolv_conf_extracts_nameservers_ignores_comments() {
        let fixture = "# comment\nnameserver 1.1.1.1\nsearch foo.local\nnameserver 8.8.8.8\n; another comment style\nnameserver  192.168.1.1  \n";
        assert_eq!(
            parse_resolv_conf(fixture),
            vec!["1.1.1.1", "8.8.8.8", "192.168.1.1"]
        );
    }

    #[test]
    fn parse_resolv_conf_returns_empty_for_no_nameservers() {
        let fixture = "search foo.local\noptions edns0\n";
        assert!(parse_resolv_conf(fixture).is_empty());
    }

    #[test]
    fn parse_proc_net_route_finds_default_route_v4() {
        let fixture = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                       eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route_v4(fixture), Some("192.168.1.1".to_string()));
    }

    #[test]
    fn parse_proc_net_route_returns_none_when_no_default() {
        let fixture = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route_v4(fixture), None);
    }

    #[test]
    fn parse_osrelease_trims() {
        assert_eq!(
            parse_osrelease("5.14.0-427.20.1.el9_4.x86_64\n"),
            Some("5.14.0-427.20.1.el9_4.x86_64".to_string())
        );
        assert_eq!(parse_osrelease(""), None);
    }
}
