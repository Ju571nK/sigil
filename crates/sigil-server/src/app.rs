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
    /// Loaded + verified at boot. Read-only thereafter. Free if none configured.
    pub license_state: sigil_core::license::status::LicenseState,
    /// Rolling window (days) for active-host counting.
    pub active_window_days: u32,
}

pub type SharedState = Arc<AppState>;

pub fn build_router(state: SharedState) -> Router {
    use crate::auth::require_bearer;
    use axum::middleware::from_fn_with_state;

    let token = state.read_token.clone();
    Router::new()
        .route("/v1/events", post(crate::events_route::post_events))
        .route("/v1/policy", get(crate::policy_route::get_policy))
        .route("/v1/healthz", get(crate::routes::healthz::get_healthz))
        .route(
            "/v1/meta",
            get(crate::routes::meta::get_meta)
                .route_layer(from_fn_with_state(token.clone(), require_bearer)),
        )
        .route(
            "/v1/policy/meta",
            get(crate::routes::policy_meta::get_policy_meta)
                .route_layer(from_fn_with_state(token.clone(), require_bearer)),
        )
        .route(
            "/v1/fleet/hosts",
            get(crate::routes::fleet_hosts::get_fleet_hosts)
                .route_layer(from_fn_with_state(token.clone(), require_bearer)),
        )
        .route(
            "/v1/fleet/hosts/:host_id",
            get(crate::routes::fleet_hosts::get_fleet_host_by_id)
                .route_layer(from_fn_with_state(token.clone(), require_bearer)),
        )
        .route(
            "/v1/fleet/risk",
            get(crate::routes::fleet_risk::get_fleet_risk)
                .route_layer(from_fn_with_state(token.clone(), require_bearer)),
        )
        .route(
            "/v1/fleet/compliance",
            get(crate::routes::fleet_compliance::get_fleet_compliance)
                .route_layer(from_fn_with_state(token.clone(), require_bearer)),
        )
        .route(
            "/v1/events",
            get(crate::routes::events::get_events)
                .route_layer(from_fn_with_state(token.clone(), require_bearer)),
        )
        .route(
            "/v1/events/:event_id",
            get(crate::routes::events::get_event_by_id)
                .route_layer(from_fn_with_state(token.clone(), require_bearer)),
        )
        .with_state(state)
}
