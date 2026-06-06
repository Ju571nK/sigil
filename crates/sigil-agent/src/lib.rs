//! Internal library shared with integration tests.

pub mod ai_guard;
pub mod cli;
pub mod control;
pub mod control_client;
pub mod debouncer;
pub mod doctor;
pub mod gc_config;
pub mod hasher;
pub mod heartbeat;
pub mod hook_deny;
pub mod hook_silence;
// The hook listener uses Unix-domain sockets (tokio UnixListener); Windows agent
// IPC is a named pipe (see control.rs) and a named-pipe hook listener is a
// follow-up, so the module is unix-only for Stage 1.
#[cfg(unix)]
pub mod hook_decide_listener;
#[cfg(unix)]
pub mod hook_listener;
pub mod host_meta_snapshot;
pub mod host_meta_snapshot_task;
pub mod host_meta_task;
pub mod jsonl_gc;
pub mod jsonl_gc_task;
pub mod normalizer;
pub mod platform;
pub mod policy_apply;
pub mod policy_expiry_task;
pub mod policy_reload_task;
pub mod runtime;
pub mod sender_offset;
pub mod show;
pub mod silence_task;
pub mod sink_task;
pub mod state_task;
pub mod supervisor;
pub mod test_support;
pub mod watcher;
