//! Cross-platform trait surface used by the runtime. The implementing module
//! is selected at compile time below.

use andeda_core::host_id::HostIdResolver;
use andeda_core::policy::expand::UserEnumerator;

pub trait Platform: HostIdResolver + UserEnumerator + Send + Sync {
    /// Probe whether Full Disk Access (or equivalent) is granted.
    /// On Windows this returns `FdaState::Granted` unconditionally.
    fn fda_state(&self) -> FdaState;
    fn name(&self) -> &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdaState {
    Granted,
    Denied,
    Unknown,
}

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacosPlatform as ActivePlatform;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsPlatform as ActivePlatform;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub mod stub;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub use stub::StubPlatform as ActivePlatform;
