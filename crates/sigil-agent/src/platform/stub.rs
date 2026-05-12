//! Fallback `Platform` for build targets without a real implementation.
//!
//! macOS, Windows, and Linux each have their own module; this stub is gated to
//! everything else (`not(any(macos, windows, linux))`) so the workspace still
//! compiles on, e.g., a BSD. It is best-effort: an empty user list,
//! `FdaState::Granted`, a fresh UUID host_id, and whatever a few Linux-style
//! files (`/etc/machine-id`, `/proc/cpuinfo`) happen to yield (often nothing).

use super::{FdaState, Platform};
use sigil_core::host_id::HostIdResolver;
use sigil_core::policy::expand::{UserContext, UserEnumerator};
use uuid::Uuid;

pub struct StubPlatform;

impl Default for StubPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl StubPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Platform for StubPlatform {
    fn fda_state(&self) -> FdaState {
        FdaState::Granted
    }
    fn name(&self) -> &'static str {
        "stub"
    }
}

impl HostIdResolver for StubPlatform {
    fn machine_id(&self) -> Option<String> {
        None
    }
    fn hostname(&self) -> Option<String> {
        std::env::var("HOSTNAME").ok()
    }
    fn fresh_uuid(&self) -> String {
        Uuid::new_v4().to_string()
    }
}

impl UserEnumerator for StubPlatform {
    fn list(&self) -> Vec<UserContext> {
        Vec::new()
    }
}

use super::hw_fingerprint::HardwareFingerprint;

impl HardwareFingerprint for StubPlatform {
    fn platform_uuid(&self) -> String {
        std::fs::read_to_string("/etc/machine-id")
            .unwrap_or_default()
            .trim()
            .to_string()
    }
    fn stable_mac(&self) -> String {
        // No portable way to do this here; the real platform modules implement it.
        String::new()
    }
    fn cpu_brand(&self) -> String {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                for line in s.lines() {
                    if let Some(rest) = line.strip_prefix("model name") {
                        if let Some(idx) = rest.find(':') {
                            return Some(rest[idx + 1..].trim().to_string());
                        }
                    }
                }
                None
            })
            .unwrap_or_default()
    }
}
