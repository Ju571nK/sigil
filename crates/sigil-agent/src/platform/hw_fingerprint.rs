//! Hardware fingerprint trait + computation.
//!
//! Spec §1.4: `hw_fingerprint = blake3(platform_uuid || stable_mac || cpu_brand)`.
//! Sanity check, NOT a security boundary.

/// Components a platform must surface to compute the fingerprint.
pub trait HardwareFingerprint {
    /// macOS `IOPlatformUUID`, Windows `MachineGuid`, Linux `/etc/machine-id`.
    /// Empty string if unavailable (degraded fingerprint, still computes).
    fn platform_uuid(&self) -> String;

    /// Lowest lexicographic non-virtual physical MAC, with the spec exclusion
    /// list applied. Empty string if no qualifying interface exists at boot.
    fn stable_mac(&self) -> String;

    /// CPU brand string, OS-provided. Empty string if unavailable.
    fn cpu_brand(&self) -> String;
}

/// Compute the fingerprint hex digest from a `HardwareFingerprint` provider.
pub fn compute<P: HardwareFingerprint>(p: &P) -> String {
    let pu = p.platform_uuid();
    let sm = p.stable_mac();
    let cb = p.cpu_brand();
    let mut hasher = blake3::Hasher::new();
    hasher.update(pu.as_bytes());
    hasher.update(b"|");
    hasher.update(sm.as_bytes());
    hasher.update(b"|");
    hasher.update(cb.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Apply the spec §1.4 exclusion list to a candidate interface name.
/// Returns `true` if the interface should be EXCLUDED.
pub fn is_excluded_iface(name: &str) -> bool {
    let n = name.to_lowercase();
    if n.starts_with("lo") || n == "lo0" {
        return true;
    }
    if n.starts_with("awdl") || n.starts_with("llw") || n.starts_with("utun") {
        return true;
    }
    if n.contains("hyper-v") || n.contains("vethernet") {
        return true;
    }
    if n.starts_with("docker")
        || n.starts_with("veth")
        || n.starts_with("br-")
        || n.starts_with("virbr")
        || n.starts_with("tun")
        || n.starts_with("tap")
    {
        return true;
    }
    if n.contains("bluetooth") || n.contains("pan") || n.contains("usb-tether") {
        return true;
    }
    false
}

/// Pick the lexicographically smallest MAC across non-excluded physical
/// interfaces, preferring Ethernet over Wi-Fi if a hint is available.
/// Returns empty string if no qualifying interface exists.
pub fn pick_stable_mac<I, F>(ifaces: I, name_hint: F) -> String
where
    I: IntoIterator<Item = (String, [u8; 6])>,
    F: Fn(&str) -> IfaceKind,
{
    let mut candidates: Vec<(String, [u8; 6], IfaceKind)> = ifaces
        .into_iter()
        .filter(|(name, _)| !is_excluded_iface(name))
        .map(|(name, mac)| {
            let kind = name_hint(&name);
            (name, mac, kind)
        })
        .collect();
    if candidates.is_empty() {
        return String::new();
    }
    let has_ethernet = candidates
        .iter()
        .any(|(_, _, k)| matches!(k, IfaceKind::Ethernet));
    if has_ethernet {
        candidates.retain(|(_, _, k)| matches!(k, IfaceKind::Ethernet | IfaceKind::Other));
    }
    candidates.sort_by_key(|(_, mac, _)| *mac);
    let mac = candidates[0].1;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Best-effort interface kind classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IfaceKind {
    Ethernet,
    WiFi,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        platform_uuid: String,
        stable_mac: String,
        cpu_brand: String,
    }
    impl HardwareFingerprint for Mock {
        fn platform_uuid(&self) -> String {
            self.platform_uuid.clone()
        }
        fn stable_mac(&self) -> String {
            self.stable_mac.clone()
        }
        fn cpu_brand(&self) -> String {
            self.cpu_brand.clone()
        }
    }

    fn clone(m: &Mock) -> Mock {
        Mock {
            platform_uuid: m.platform_uuid.clone(),
            stable_mac: m.stable_mac.clone(),
            cpu_brand: m.cpu_brand.clone(),
        }
    }

    #[test]
    fn fingerprint_is_deterministic_for_same_inputs() {
        let m = Mock {
            platform_uuid: "AAA".into(),
            stable_mac: "00:11:22:33:44:55".into(),
            cpu_brand: "Apple M2".into(),
        };
        assert_eq!(compute(&m), compute(&m));
    }

    #[test]
    fn fingerprint_changes_when_any_component_changes() {
        let base = Mock {
            platform_uuid: "AAA".into(),
            stable_mac: "00:11:22:33:44:55".into(),
            cpu_brand: "Apple M2".into(),
        };
        let with_diff_uuid = Mock {
            platform_uuid: "BBB".into(),
            ..clone(&base)
        };
        let with_diff_mac = Mock {
            stable_mac: "ff:ee:dd:cc:bb:aa".into(),
            ..clone(&base)
        };
        let with_diff_cpu = Mock {
            cpu_brand: "Intel i9".into(),
            ..clone(&base)
        };
        assert_ne!(compute(&base), compute(&with_diff_uuid));
        assert_ne!(compute(&base), compute(&with_diff_mac));
        assert_ne!(compute(&base), compute(&with_diff_cpu));
    }

    #[test]
    fn empty_inputs_still_produce_a_hash() {
        let m = Mock {
            platform_uuid: "".into(),
            stable_mac: "".into(),
            cpu_brand: "".into(),
        };
        let h = compute(&m);
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn exclusion_list_filters_loopback_and_virtual() {
        for name in [
            "lo0",
            "docker0",
            "veth1234",
            "awdl0",
            "utun3",
            "br-abcdef",
            "Bluetooth PAN",
        ] {
            assert!(is_excluded_iface(name), "expected {name} to be excluded");
        }
        for name in ["en0", "eth0", "Ethernet 1", "Wi-Fi"] {
            assert!(!is_excluded_iface(name), "expected {name} NOT excluded");
        }
    }

    #[test]
    fn pick_prefers_ethernet_over_wifi() {
        let ifaces = vec![
            ("en1".to_string(), [0x10, 0x20, 0x30, 0x40, 0x50, 0x60]),
            ("en0".to_string(), [0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0]),
        ];
        let kind = |n: &str| {
            if n == "en0" {
                IfaceKind::Ethernet
            } else {
                IfaceKind::WiFi
            }
        };
        let mac = pick_stable_mac(ifaces, kind);
        assert_eq!(mac, "90:a0:b0:c0:d0:e0");
    }

    #[test]
    fn pick_returns_empty_when_all_excluded() {
        let ifaces = vec![("lo0".to_string(), [0; 6]), ("docker0".to_string(), [1; 6])];
        let mac = pick_stable_mac(ifaces, |_| IfaceKind::Other);
        assert_eq!(mac, "");
    }

    #[test]
    fn pick_lexicographic_smallest_when_no_ethernet_hint() {
        let ifaces = vec![
            ("en1".to_string(), [0xff, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ("en2".to_string(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ];
        let mac = pick_stable_mac(ifaces, |_| IfaceKind::Other);
        assert_eq!(mac, "00:11:22:33:44:55");
    }
}
