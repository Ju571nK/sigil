//! Stub platform for non-macOS/Windows builds (Phase 1 build-only — Linux etc.).
//!
//! Spec section 6 declares Linux build-only for Phase 1. This stub satisfies the
//! `Platform` trait so the workspace compiles on CI Linux runners. It is not
//! exercised at runtime because the runtime is gated to macOS/Windows in
//! deployment artifacts; if the daemon is ever launched on an unsupported OS
//! it returns an empty user list, `FdaState::Granted`, and a fresh UUID host_id.

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
        // Phase 2 Linux is build-only; runtime is Phase 2+. Empty.
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
