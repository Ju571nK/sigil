//! ANDEDA core domain library.
//!
//! This crate is OS-, tokio-, and notify-independent. All filesystem-watching,
//! async-runtime, and platform-specific code lives in `andeda-agent`.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// Modules will be added by subsequent tasks.
