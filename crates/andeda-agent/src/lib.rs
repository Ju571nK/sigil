//! Internal library shared with integration tests.

pub mod cli;
pub mod control;
pub mod policy_apply;
pub mod debouncer;
pub mod doctor;
pub mod hasher;
pub mod heartbeat;
pub mod host_meta_task;
pub mod normalizer;
pub mod platform;
pub mod policy_expiry_task;
pub mod runtime;
pub mod show;
pub mod sink_task;
pub mod state_task;
pub mod supervisor;
pub mod test_support;
pub mod watcher;
pub mod sender_offset;
pub mod gc_config;
pub mod jsonl_gc;
pub mod jsonl_gc_task;
