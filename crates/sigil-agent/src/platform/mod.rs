//! Cross-platform trait surface used by the runtime. The implementing module
//! is selected at compile time below.

use sigil_core::host_id::HostIdResolver;
use sigil_core::policy::expand::UserEnumerator;

pub trait Platform: HostIdResolver + UserEnumerator + Send + Sync {
    /// Probe whether Full Disk Access (or equivalent) is granted.
    /// On Windows this returns `FdaState::Granted` unconditionally.
    fn fda_state(&self) -> FdaState;
    fn name(&self) -> &'static str;

    /// Phase 3b.4-pre — kernel version string. None if unavailable.
    fn kernel_version(&self) -> Option<String> {
        None
    }

    /// Phase 3b.4-pre — default IPv4 gateway as dotted-quad string.
    /// None if no default route or discovery fails.
    fn default_gateway_v4(&self) -> Option<String> {
        None
    }

    /// Phase 3b.4-pre — default IPv6 gateway. None if no default route.
    fn default_gateway_v6(&self) -> Option<String> {
        None
    }

    /// Phase 3b.4-pre — system resolver DNS server IPs (IPv4 + IPv6 mixed).
    /// Empty Vec if discovery fails.
    fn dns_servers(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdaState {
    Granted,
    Denied,
    Unknown,
}

pub mod hw_fingerprint;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosPlatform as ActivePlatform;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsPlatform as ActivePlatform;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxPlatform as ActivePlatform;

// Fallback for any OS that isn't macOS / Windows / Linux: build-only stub.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub mod stub;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub use stub::StubPlatform as ActivePlatform;
