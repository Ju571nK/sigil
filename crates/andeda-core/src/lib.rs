//! ANDEDA core domain library.
//!
//! This crate is OS-, tokio-, and notify-independent.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod debounce;
pub mod event;
pub mod hashing;
pub mod host_id;
pub mod host_meta;
pub mod policy;
pub mod ratelimit;
pub mod sink;
pub mod state;
pub mod stats;

pub use event::PolicySignatureInvalidReason;
pub use host_meta::HostMeta;
