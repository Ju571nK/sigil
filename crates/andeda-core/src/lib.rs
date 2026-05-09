//! ANDEDA core domain library.
//!
//! This crate is OS-, tokio-, and notify-independent.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod event;
pub mod hashing;
pub mod policy;
