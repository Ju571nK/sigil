//! Shared app state + router assembly.

use crate::auth::ReadToken;
use crate::fleet_index::FleetIndex;
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
    /// Phase 3b.4 — in-memory per-host summary index. Updated synchronously
    /// inside the POST /v1/events handler after a successful persist.
    pub fleet_index: FleetIndex,
    /// Phase 3b.4 — bearer token for the read API. `None` ⇒ read endpoints 404.
    pub read_token: ReadToken,
}

pub type SharedState = Arc<AppState>;

pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/v1/events", post(crate::events_route::post_events))
        .route("/v1/policy", get(crate::policy_route::get_policy))
        .with_state(state)
}
