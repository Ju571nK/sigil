//! Shared test helpers — currently the axum mock server.

#![allow(dead_code)] // helpers are referenced by individual integration test files

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use sigil_sender::wire::{EventsAccepted, EventsRequest};

/// Per-test mock state.
pub struct MockState {
    pub received_batches: Vec<EventsRequest>,
    pub next_status: u16,          // override for next response (default 200)
    pub next_body: Option<String>, // override body
    pub policy_etag: String,
    pub policy_response: Option<sigil_sender::wire::SignedPolicyResponse>,
}

impl Default for MockState {
    fn default() -> Self {
        MockState {
            received_batches: Vec::new(),
            next_status: 200,
            next_body: None,
            policy_etag: String::new(),
            policy_response: None,
        }
    }
}

pub type SharedMock = Arc<Mutex<MockState>>;

pub async fn spawn_mock() -> (SocketAddr, SharedMock) {
    let state: SharedMock = Arc::new(Mutex::new(MockState {
        next_status: 200,
        policy_etag: String::new(),
        ..Default::default()
    }));
    let app = Router::new()
        .route("/v1/events", post(handle_events))
        .route("/v1/policy", get(handle_policy))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, state)
}

async fn handle_events(
    State(state): State<SharedMock>,
    Json(req): Json<EventsRequest>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let mut s = state.lock().await;
    s.received_batches.push(req.clone());
    let status = s.next_status;
    if (200..300).contains(&status) {
        let resp = EventsAccepted {
            accepted: req.events.iter().map(|e| e.event_id).collect(),
            rejected: vec![],
            high_water_event_id: req
                .events
                .last()
                .map(|e| e.event_id)
                .unwrap_or_else(uuid::Uuid::nil),
        };
        (
            axum::http::StatusCode::from_u16(status).unwrap(),
            Json(serde_json::to_value(resp).unwrap()),
        )
    } else {
        let body = s.next_body.clone().unwrap_or_default();
        (
            axum::http::StatusCode::from_u16(status).unwrap(),
            Json(serde_json::json!({"error": body})),
        )
    }
}

async fn handle_policy(
    State(state): State<SharedMock>,
    headers: axum::http::HeaderMap,
) -> (
    axum::http::StatusCode,
    axum::http::HeaderMap,
    Json<serde_json::Value>,
) {
    let s = state.lock().await;
    let mut out_headers = axum::http::HeaderMap::new();
    if let Some(etag) = headers.get("if-none-match") {
        if etag.to_str().unwrap_or("") == s.policy_etag {
            return (
                axum::http::StatusCode::NOT_MODIFIED,
                out_headers,
                Json(serde_json::json!(null)),
            );
        }
    }
    out_headers.insert(
        "etag",
        axum::http::HeaderValue::from_str(&s.policy_etag).unwrap(),
    );
    let body = s
        .policy_response
        .as_ref()
        .map(|r| serde_json::to_value(r).unwrap())
        .unwrap_or(serde_json::json!(null));
    (axum::http::StatusCode::OK, out_headers, Json(body))
}
