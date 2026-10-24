#![cfg(all(unix, feature = "test-util"))]
//! T-13c (#312): a full observation queue drops pages, and a dropped page can
//! only make a listing incomplete, never complete. Needs the worker pause knob
//! (`test-util`).

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use sigil_proxy::inventory::{CursorHasher, InventoryEngine, InventoryLimits};
use sigil_proxy::inventory_sink::{InventorySink, QUEUE_DEPTH};
use sigil_proxy::mcp::observation::{
    CallRef, Cause, Completed, Delivery, Method, NextCursor, Observation, ObservationSink, Outcome,
    RequestStarted, ToolDescriptor, ToolListCapture, ToolListPage,
};
use sigil_proxy::mcp::{RequestId, ToolField, ToolName};
use sigil_proxy::registry_key::ScopeKey;
use sigil_proxy::registry_store::RegistryStore;
use sigil_proxy::route::RouteScope;

const EPOCH: &str = "0f0f0f0f-1111-4222-8333-444444444444";

fn poll_ready_start(
    future: sigil_proxy::mcp::observation::SinkFuture<
        '_,
        sigil_proxy::mcp::observation::StartVerdict,
    >,
) {
    let mut future = future;
    assert!(future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        .is_ready());
}

fn page(name: &str, next: Option<&str>) -> Option<ToolListCapture> {
    Some(ToolListCapture::Page(ToolListPage {
        tools: vec![ToolDescriptor {
            name: ToolName::parse(name).unwrap(),
            definition: json!({"name": name, "inputSchema": {"type": "object"}})
                .to_string()
                .into(),
        }],
        next_cursor: next.map(|n| NextCursor::new(n).unwrap()),
    }))
}

#[tokio::test]
async fn a_dropped_page_never_makes_a_listing_complete() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (store, _) = RegistryStore::open(d.path(), "px-1").unwrap();
    let engine = InventoryEngine::new(store.clone(), EPOCH, InventoryLimits::default());
    let hasher = CursorHasher::new().unwrap();
    let (sink, handle) = InventorySink::start(engine, hasher.clone(), "px-1").unwrap();

    let mut seq = 0u64;
    let mut send = |principal: &str, cursor: Option<&str>, capture| {
        seq += 1;
        let call = CallRef {
            seq,
            route_id: "r1".into(),
            principal_id: principal.into(),
            scope: Some(Arc::new(RouteScope {
                upstream_id: "up-1".into(),
                credential_scope_id: "cs-1".into(),
            })),
            audit: None,
            session: Some(session_of(principal)),
        };
        let id = RequestId::from_raw("1").unwrap();
        let started = RequestStarted {
            call: call.clone(),
            method: Method::ToolsList,
            request_id: id.clone(),
            tool: ToolField::NotApplicable,
            list_cursor: cursor.map(|c| hasher.tag(c)),
            task_augmented: false,
            request_bytes: 1,
            received_at: SystemTime::now(),
        };
        drop(sink.request_started(&started));
        sink.observe(Observation::Completed(Completed {
            call,
            method: Method::ToolsList,
            request_id: id,
            outcome: Outcome::Success,
            delivery: Delivery::Sent,
            cause: Cause::None,
            http_status: Some(200),
            response_bytes: 1,
            duration: Duration::from_millis(1),
            completed_at: SystemTime::now(),
            cancel_requested: false,
            tool_list: capture,
        }));
    };

    // Page 1 is queued, then the worker stalls and the queue fills up with other
    // principals' pages, so the page that would complete the listing is dropped.
    sink.pause_worker_for_test(true);
    send("pr", None, page("a", Some("C1")));
    // The worker may already hold page 1 (paused on its next message): one slot
    // more than the queue depth is needed at most.
    for i in 0..(QUEUE_DEPTH + 2) {
        send(&format!("filler{i}"), None, page("f", Some("F")));
    }
    send("pr", Some("C1"), page("b", None));
    assert!(sink.dropped_pages() > 0, "the queue overflowed");
    sink.pause_worker_for_test(false);
    handle.shutdown().await;

    let reports: Vec<Value> = store
        .pending_reports(1000)
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    assert!(
        reports.iter().all(|r| r["completeness"] == "incomplete"),
        "no listing may be complete"
    );
    assert!(store
        .latest_snapshot(&ScopeKey::live("px-1", "up-1", "cs-1"))
        .unwrap()
        .is_none());
}

/// T-12b2: inventory chains belong to a proxy session; each principal of these
/// tests stands for one session of its own.
fn session_of(principal: &str) -> u64 {
    principal
        .bytes()
        .fold(7u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)))
}

#[tokio::test]
async fn a_session_end_waits_for_capacity_instead_of_disappearing() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (store, _) = RegistryStore::open(d.path(), "px-1").unwrap();
    let engine = InventoryEngine::new(store.clone(), EPOCH, InventoryLimits::default());
    let hasher = CursorHasher::new().unwrap();
    let (sink, handle) = InventorySink::start(engine, hasher.clone(), "px-1").unwrap();
    let call = CallRef {
        seq: 1,
        route_id: "r1".into(),
        principal_id: "pr".into(),
        scope: Some(Arc::new(sigil_proxy::route::RouteScope {
            upstream_id: "up-1".into(),
            credential_scope_id: "cs-1".into(),
        })),
        audit: None,
        session: Some(session_of("pr")),
    };
    let id = RequestId::from_raw("1").unwrap();
    let start = RequestStarted {
        call: call.clone(),
        method: Method::ToolsList,
        request_id: id.clone(),
        tool: ToolField::NotApplicable,
        list_cursor: None,
        task_augmented: false,
        request_bytes: 1,
        received_at: SystemTime::now(),
    };
    poll_ready_start(sink.request_started(&start));
    sink.observe(Observation::Completed(Completed {
        call,
        method: Method::ToolsList,
        request_id: id,
        outcome: Outcome::Success,
        delivery: Delivery::Sent,
        cause: Cause::None,
        http_status: Some(200),
        response_bytes: 1,
        duration: Duration::from_millis(1),
        completed_at: SystemTime::now(),
        cancel_requested: false,
        tool_list: page("a", Some("C1")),
    }));
    sink.pause_worker_for_test(true);
    for i in 0..(QUEUE_DEPTH + 1) {
        let c = CallRef {
            seq: i as u64 + 2,
            route_id: "r1".into(),
            principal_id: format!("f{i}"),
            scope: Some(Arc::new(sigil_proxy::route::RouteScope {
                upstream_id: "up-1".into(),
                credential_scope_id: "cs-1".into(),
            })),
            audit: None,
            session: Some(i as u64 + 100),
        };
        let rid = RequestId::from_raw("1").unwrap();
        // No started fact: each completion queues a fail-closed Abort marker,
        // filling the bounded queue without opening extra inventory chains.
        sink.observe(Observation::Completed(Completed {
            call: c,
            method: Method::ToolsList,
            request_id: rid,
            outcome: Outcome::Success,
            delivery: Delivery::Sent,
            cause: Cause::None,
            http_status: Some(200),
            response_bytes: 1,
            duration: Duration::from_millis(1),
            completed_at: SystemTime::now(),
            cancel_requested: false,
            tool_list: page("f", Some("F")),
        }));
    }
    sink.end_session(session_of("pr"));
    sink.pause_worker_for_test(false);
    handle.shutdown().await;
    let reports: Vec<Value> = store
        .pending_reports(1000)
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    assert_eq!(
        reports
            .iter()
            .filter(|r| r["incomplete_reason"] == "session_ended")
            .count(),
        1,
        "the saturated queue must close the real session chain exactly once"
    );
}
