//! Shared app state + router assembly.

use crate::auth::ReadToken;
use crate::fleet_index::FleetIndex;
use crate::persist::HighWater;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum::{routing::get, routing::post, Router};
use serde_json::json;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Audit signing key (auto-generated). `None` ⇒ audit signing disabled.
    pub audit_key: Option<crate::audit_key::AuditKey>,
    /// Latest signed audit-chain head, updated by the audit task; read by /v1/meta.
    pub audit_head: Mutex<Option<sigil_core::audit::AuditHead>>,
}

pub type SharedState = Arc<AppState>;

/// Health-check route path. Referenced by both the route registration and the
/// `boot_gate` middleware (which always lets it through), so it lives in one
/// place to keep the two in sync under rename.
pub const HEALTHZ_PATH: &str = "/v1/healthz";

pub fn build_router(state: SharedState) -> Router {
    use crate::auth::require_bearer;
    use axum::middleware::from_fn_with_state;

    let token = state.read_token.clone();
    Router::new()
        .route("/v1/events", post(crate::events_route::post_events))
        .route("/v1/policy", get(crate::policy_route::get_policy))
        .route(HEALTHZ_PATH, get(crate::routes::healthz::get_healthz))
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

/// Boot-gate middleware. While the in-memory fleet index is still being rebuilt
/// (`boot_complete == false`), every route except `/v1/healthz` returns
/// 503 + `Retry-After: 5` so agent senders and consoles back off and retry (#19).
pub async fn boot_gate(
    State(boot_complete): State<Arc<AtomicBool>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if req.uri().path() == HEALTHZ_PATH || boot_complete.load(Ordering::Relaxed) {
        return next.run(req).await;
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "5")],
        Json(json!({"error": {"code": "rebuilding", "message": "fleet index rebuilding; retry shortly"}})),
    )
        .into_response()
}
