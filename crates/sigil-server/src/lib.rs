//! OSS reference server for the Sigil Phase 2 control + event plane.
//!
//! Implements the host-facing HTTP contract from spec §3.8.2:
//! - `POST /v1/events` — accept event batches, persist as per-host JSONL,
//!   return `{accepted, rejected, high_water_event_id}`.
//! - `GET /v1/policy?host_id=X` — serve the operator-signed policy bundle
//!   with ETag-based 304 handling.
//!
//! Auth model (v1): trust any client cert signed by the configured client
//! CA (mTLS = "fleet member"); `host_id` is read from the request body; an
//! optional `hosts.json` allowlist gates which `host_id`s are accepted.
//! Per-host cert-fingerprint binding (the spec's 409 path) is a v2 item.
//!
//! This is the *mechanism* reference — the commercial hosted service
//! (multi-tenant, cert issuance, SIEM forwarding) is a separate deliverable.

pub mod allowlist;
pub mod app;
pub mod cli;
pub mod config;
pub mod events_route;
pub mod persist;
pub mod policy_route;
pub mod auth;
pub mod boot_rebuild;
pub mod fleet_index;
pub mod fleet_index_update;
pub mod jsonl_scan;
pub mod routes;
