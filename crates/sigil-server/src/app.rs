//! Shared app state + router assembly.

use crate::persist::HighWater;
use axum::{routing::get, routing::post, Router};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub events_out_dir: PathBuf,
    pub policy_bundle_path: PathBuf,
    pub high_water_path: PathBuf,
    /// `None` ⇒ every authenticated host is accepted.
    pub allowlist: Option<HashSet<String>>,
    /// host_id → highest persisted sequence. Guards the JSONL append + dedup.
    pub high_water: Mutex<HighWater>,
}

pub type SharedState = Arc<AppState>;

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/v1/events", post(crate::events_route::post_events))
        .route("/v1/policy", get(crate::policy_route::get_policy))
        .with_state(state)
}
