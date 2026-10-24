//! Sigil Proxy skeleton (T-10): CLI, local bootstrap, limits and lifecycle.
//!
//! The proxy is its own binary and process. There is no network relay here
//! (T-12); `run` only validates the bootstrap, takes the `state_dir` lock,
//! writes the local status file and waits for a termination signal.

pub mod body;
pub mod bootstrap;
pub mod cli;
pub mod config_sync;
pub mod dest;
pub mod fsutil;
pub mod headers;
pub mod ingest_client;
pub mod inventory;
pub mod inventory_sink;
pub mod invocation_sink;
pub mod jcs;
pub mod lifecycle;
pub mod limits;
pub mod mcp;
pub mod registry_client;
pub mod registry_key;
pub mod registry_store;
pub mod route;
pub mod route_health;
pub mod server;
pub mod session;
pub mod spool;
pub mod state_dir;
pub mod status_report;
pub mod tls;
pub mod token;
