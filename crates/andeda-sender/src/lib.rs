//! ANDEDA Phase 2 sender process.
//!
//! See `docs/superpowers/specs/2026-05-08-andeda-design.md` §3.8.

pub mod batch_reader;
pub mod cli;
pub mod config;
pub mod control_task;
pub mod data_task;
pub mod dead_letter;
pub mod heartbeat;
pub mod manifest;
pub mod state;
pub mod transport;
pub mod wire;
