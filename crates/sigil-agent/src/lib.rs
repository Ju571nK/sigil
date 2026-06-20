//! Internal library shared with integration tests.

pub mod ai_guard;
#[cfg(feature = "operator-cli")]
pub mod assess_cli;
pub mod cli;
pub mod control;
pub mod control_client;
pub mod debouncer;
pub mod doctor;
pub mod effective_policy;
pub mod gc_config;
pub mod hasher;
pub mod heartbeat;
pub mod hook_deny;
pub mod hook_silence;
// `hook_event` holds the cross-platform event-conversion helpers (`to_event`).
// The one-way `hook_listener` (observe) is a Unix-socket listener — unix-only.
// The two-way `hook_decide_listener` (enforce) serves a Unix socket on Unix and
// a named pipe on Windows (#162), so it compiles on both.
pub mod hook_decide_listener;
pub mod hook_event;
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
pub mod rule_packs_watch;
pub mod runtime;
pub mod scan_cli;
pub mod sender_offset;
pub mod show;
pub mod silence_task;
pub mod sink_task;
pub mod state_task;
pub mod supervisor;
pub mod test_support;
pub mod watcher;
