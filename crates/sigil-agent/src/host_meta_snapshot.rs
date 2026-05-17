//! Phase 3b.4-pre — collect a full host metadata snapshot
//! (hostname / OS / interfaces / DNS / gateways) for emission by
//! host_meta_snapshot_task. Pure data-gathering. Best-effort — individual
//! field failures degrade to None / empty Vec; never propagate as Err.

use crate::platform::{ActivePlatform, Platform};
use sigil_core::event::{HostMetaSnapshot, NetworkInterface};
use sigil_core::host_id::HostIdResolver;

/// Collect the snapshot from the running host.
pub fn collect(platform: &ActivePlatform) -> HostMetaSnapshot {
    HostMetaSnapshot {
        hostname: platform.hostname(),
        os_name: os_info_name(),
        os_version: os_info_version(),
        kernel_version: platform.kernel_version(),
        architecture: Some(std::env::consts::ARCH.to_string()),
        interfaces: collect_interfaces(),
        default_gateway_v4: platform.default_gateway_v4(),
        default_gateway_v6: platform.default_gateway_v6(),
        dns_servers: platform.dns_servers(),
    }
}

/// Deterministic 32-byte hash of a snapshot for change detection. Two
/// equal snapshots produce the same hash regardless of capture time;
/// interface order is normalized via BTreeMap inside `collect_interfaces`.
pub fn snapshot_hash(snapshot: &HostMetaSnapshot) -> [u8; 32] {
    let canonical = serde_json::to_string(snapshot).expect("HostMetaSnapshot is Serialize");
    *blake3::hash(canonical.as_bytes()).as_bytes()
}

fn os_info_name() -> Option<String> {
    let info = os_info::get();
    let t = info.os_type();
    if matches!(t, os_info::Type::Unknown) {
        None
    } else {
        Some(t.to_string())
    }
}

fn os_info_version() -> Option<String> {
    let v = os_info::get().version().to_string();
    if v == "Unknown" {
        None
    } else {
        Some(v)
    }
}

fn collect_interfaces() -> Vec<NetworkInterface> {
    let Ok(addrs) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut by_name: std::collections::BTreeMap<String, NetworkInterface> =
        std::collections::BTreeMap::new();
    for a in addrs {
        if a.is_loopback() {
            continue;
        }
        let entry = by_name
            .entry(a.name.clone())
            .or_insert_with(|| NetworkInterface {
                name: a.name.clone(),
                mac: None,
                ipv4: Vec::new(),
                ipv6: Vec::new(),
            });
        let s = format!("{}/{}", a.ip(), prefix_length_of(&a));
        match a.ip() {
            std::net::IpAddr::V4(_) => entry.ipv4.push(s),
            std::net::IpAddr::V6(_) => entry.ipv6.push(s),
        }
    }
    for (name, iface) in by_name.iter_mut() {
        iface.mac = mac_address::mac_address_by_name(name)
            .ok()
            .flatten()
            .map(|m| m.to_string().to_lowercase());
    }
    by_name.into_values().collect()
}

fn prefix_length_of(a: &if_addrs::Interface) -> u8 {
    match &a.addr {
        if_addrs::IfAddr::V4(v) => netmask_to_prefix_v4(v.netmask.octets()),
        if_addrs::IfAddr::V6(v) => netmask_to_prefix_v6(v.netmask.octets()),
    }
}

pub(crate) fn netmask_to_prefix_v4(mask: [u8; 4]) -> u8 {
    let v = u32::from_be_bytes(mask);
    v.count_ones() as u8
}

pub(crate) fn netmask_to_prefix_v6(mask: [u8; 16]) -> u8 {
    mask.iter().map(|b| b.count_ones() as u8).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::event::{HostMetaSnapshot, NetworkInterface};

    fn fixed_snapshot() -> HostMetaSnapshot {
        HostMetaSnapshot {
            hostname: Some("h".into()),
            os_name: Some("macOS".into()),
            os_version: Some("14.5".into()),
            kernel_version: Some("23.5.0".into()),
            architecture: Some("arm64".into()),
            interfaces: vec![NetworkInterface {
                name: "en0".into(),
                mac: Some("00:1b:44:11:3a:b7".into()),
                ipv4: vec!["10.0.0.1/24".into()],
                ipv6: vec![],
            }],
            default_gateway_v4: Some("10.0.0.254".into()),
            default_gateway_v6: None,
            dns_servers: vec!["1.1.1.1".into()],
        }
    }

    #[test]
    fn snapshot_hash_is_deterministic() {
        let s = fixed_snapshot();
        assert_eq!(snapshot_hash(&s), snapshot_hash(&s));
    }

    #[test]
    fn snapshot_hash_changes_when_hostname_changes() {
        let a = fixed_snapshot();
        let mut b = fixed_snapshot();
        b.hostname = Some("other".into());
        assert_ne!(snapshot_hash(&a), snapshot_hash(&b));
    }

    #[test]
    fn snapshot_hash_changes_when_interface_set_changes() {
        let a = fixed_snapshot();
        let mut b = fixed_snapshot();
        b.interfaces.push(NetworkInterface {
            name: "en1".into(),
            mac: None,
            ipv4: vec![],
            ipv6: vec![],
        });
        assert_ne!(snapshot_hash(&a), snapshot_hash(&b));
    }

    #[test]
    fn netmask_to_prefix_v4_boundaries() {
        assert_eq!(netmask_to_prefix_v4([255, 255, 255, 255]), 32);
        assert_eq!(netmask_to_prefix_v4([255, 255, 255, 0]), 24);
        assert_eq!(netmask_to_prefix_v4([255, 255, 0, 0]), 16);
        assert_eq!(netmask_to_prefix_v4([0, 0, 0, 0]), 0);
    }

    #[test]
    fn netmask_to_prefix_v6_boundaries() {
        let all_ones = [0xff; 16];
        assert_eq!(netmask_to_prefix_v6(all_ones), 128);
        let mut half = [0u8; 16];
        for b in half.iter_mut().take(8) {
            *b = 0xff;
        }
        assert_eq!(netmask_to_prefix_v6(half), 64);
        assert_eq!(netmask_to_prefix_v6([0u8; 16]), 0);
    }

    #[test]
    fn collect_returns_a_snapshot_on_real_system() {
        let plat = ActivePlatform::new();
        let s = collect(&plat);
        assert_eq!(s.architecture.as_deref(), Some(std::env::consts::ARCH));
        assert!(s.architecture.is_some());
    }
}
