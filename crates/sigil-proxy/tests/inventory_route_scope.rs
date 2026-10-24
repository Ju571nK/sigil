#![cfg(unix)]
//! T-13c (#312): a `tools/list` call is filed under the scope of the route table
//! that dispatched it. A config applied (through `ConfigSync`) while the call is
//! in flight, repointing the route to another credential scope or upstream or
//! removing it, never moves the call's tools into the new scope.
//!
//! PX-005/006, AC-05/06.

mod common;
use common::*;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use serde_json::{json, Value};
use sigil_proxy::bootstrap::Credential;
use sigil_proxy::config_sync::{ConfigSync, FetchResult, SyncOutcome};
use sigil_proxy::dest::SystemResolver;
use sigil_proxy::inventory::{CursorHasher, InventoryEngine, InventoryLimits};
use sigil_proxy::inventory_sink::InventorySink;
use sigil_proxy::mcp::observation::{
    Method, Observation, ObservationSink, RequestStarted, SinkFuture, StartVerdict,
};
use sigil_proxy::registry_key::ScopeKey;
use sigil_proxy::registry_store::RegistryStore;
use sigil_proxy::route::TableHandle;
use sigil_proxy::server::Proxy;
use sigil_proxy_api::status::ConfigState;
use std::time::Duration;
use tokio::sync::{oneshot, Notify};
use tokio::time::timeout;

const EPOCH: &str = "0f0f0f0f-1111-4222-8333-444444444444";
const CS_A: &str = "cs-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CS_B: &str = "cs-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Bound on every wait of this test: a stuck relay fails, it never hangs.
const WAIT: Duration = Duration::from_secs(20);

/// Delegates to the inventory sink, but holds the dispatch of a `tools/list`
/// (after the route was selected) until the test has applied the next config.
/// The session's `initialize` passes straight through.
struct Gate {
    inner: Arc<InventorySink>,
    entered: Notify,
    release: Notify,
}

impl ObservationSink for Gate {
    fn request_started<'a>(&'a self, s: &'a RequestStarted) -> SinkFuture<'a, StartVerdict> {
        Box::pin(async move {
            let v = self.inner.request_started(s).await;
            if s.method == Method::ToolsList {
                self.entered.notify_one();
                self.release.notified().await;
            }
            v
        })
    }
    fn observe(&self, o: Observation) {
        self.inner.observe(o)
    }
}

async fn tools_upstream() -> Up {
    Up::start(|seen| {
        let v: Value = serde_json::from_slice(&seen.body).unwrap();
        let body = json!({"jsonrpc": "2.0", "id": v["id"], "result": {"tools": [
            {"name": "t1", "description": "d", "inputSchema": {"type": "object"}}
        ]}});
        full(200, "application/json", body.to_string().as_bytes())
    })
    .await
}

/// A config document with the given `(route_id, upstream_id, credential_scope_id)`
/// routes, all on `up` and open to principal `pa` / `tok-a`.
fn config(revision: i64, up: &Up, routes: &[(&str, &str, &str)]) -> FetchResult {
    let rs: Vec<Value> = routes
        .iter()
        .map(|(r, u, c)| {
            json!({"route_id": r, "upstream_id": u, "upstream_url": up.url("/up"),
                   "upstream_protocol": "2025-11-25", "credential_ref": "up",
                   "credential_scope_id": c})
        })
        .collect();
    let ids: Vec<&str> = routes.iter().map(|r| r.0).collect();
    FetchResult::Config(
        serde_json::to_vec(&json!({
            "schema_version": 1, "proxy_id": "px-1", "revision": revision,
            "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
            "ttl_seconds": 300, "mode": "observe",
            "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
            "allowed_origins": [],
            "routes": rs,
            "principals": [{"principal_id": "pa",
                "verifiers": [{"key_id": "k1", "verifier": sigil_proxy_api::verifier_for("tok-a")}],
                "routes": ids}],
        }))
        .unwrap(),
    )
}

fn apply(sync: &mut ConfigSync, cfg: FetchResult, revision: i64) {
    assert_eq!(
        sync.on_fetch(tokio::time::Instant::now(), cfg),
        SyncOutcome::Applied { revision }
    );
}

/// One `tools/list` on route `a`, routed under config revision 1; revision 2 (if
/// any) is applied between the route selection and the dispatch, so it is the
/// installed config when the call completes. Returns the store once the engine
/// has drained.
async fn list_across_an_apply(
    up: &Up,
    before: &[(&str, &str, &str)],
    after: Option<&[(&str, &str, &str)]>,
) -> (RegistryStore, tempfile::TempDir) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let secret = d.path().join("secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let creds = BTreeMap::from([(
        "up".to_string(),
        Credential {
            secret_file: secret,
            upstream_origins: vec![format!("http://127.0.0.1:{}", up.addr.port())],
        },
    )]);
    let table = TableHandle::new();
    let mut sync = ConfigSync::new("px-1", creds, limits(), table.clone(), ConfigState::None);
    apply(&mut sync, config(1, up, before), 1);

    let (store, _) = RegistryStore::open(d.path(), "px-1").unwrap();
    let engine = InventoryEngine::new(store.clone(), EPOCH, InventoryLimits::default());
    let hasher = CursorHasher::new().unwrap();
    let (sink, handle) = InventorySink::start(engine, hasher.clone(), "px-1").unwrap();
    let gate = Arc::new(Gate {
        inner: sink,
        entered: Notify::new(),
        release: Notify::new(),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Proxy::new(limits(), table.clone(), Arc::new(SystemResolver))
        .with_sink(gate.clone() as Arc<dyn ObservationSink>, hasher);
    let (stop, rx) = oneshot::channel::<()>();
    let serve = tokio::spawn(async move {
        let _ = proxy
            .serve(listener, None, async {
                let _ = rx.await;
            })
            .await;
    });

    let post = |body: &[u8], session: Option<&str>| {
        let mut req = format!(
            "POST /mcp/a HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
             Authorization: Bearer tok-a\r\nContent-Type: application/json\r\n\
             Accept: application/json, text/event-stream\r\n{}\
             MCP-Protocol-Version: 2025-11-25\r\nContent-Length: {}\r\n\r\n",
            session
                .map(|s| format!("Mcp-Session-Id: {s}\r\n"))
                .unwrap_or_default(),
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(body);
        req
    };
    // The session the call runs in (the fixture answers the initialize).
    let init = timeout(
        WAIT,
        send_raw(addr, &post(initialize_body("0").as_bytes(), None)),
    )
    .await
    .expect("initialize answered");
    assert_eq!(init.status, 200, "{}", init.text());
    let sid = init
        .header("mcp-session-id")
        .expect("session issued")
        .to_string();

    let req = post(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        Some(&sid),
    );
    let call = tokio::spawn(async move { send_raw(addr, &req).await });

    timeout(WAIT, gate.entered.notified())
        .await
        .expect("the tools/list reached the gate");
    if let Some(a) = after {
        apply(&mut sync, config(2, up, a), 2);
    }
    gate.release.notify_one();
    let r = timeout(WAIT, call).await.expect("call answered").unwrap();
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(up.count(), 1);

    let _ = stop.send(());
    timeout(WAIT, serve).await.expect("relay drained").unwrap();
    timeout(WAIT, handle.shutdown())
        .await
        .expect("inventory drained");
    (store, d)
}

fn snapshot_in(store: &RegistryStore, upstream_id: &str, cs: &str) -> bool {
    store
        .latest_snapshot(&ScopeKey::live("px-1", upstream_id, cs))
        .unwrap()
        .is_some()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_without_an_apply_is_filed_under_its_route_scope() {
    let up = tools_upstream().await;
    let (store, _d) = list_across_an_apply(&up, &[("a", "up-1", CS_A)], None).await;
    assert!(snapshot_in(&store, "up-1", CS_A));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_scope_change_in_flight_keeps_the_original_scope() {
    let up = tools_upstream().await;
    let (store, _d) =
        list_across_an_apply(&up, &[("a", "up-1", CS_A)], Some(&[("a", "up-1", CS_B)])).await;
    assert!(snapshot_in(&store, "up-1", CS_A));
    assert!(!snapshot_in(&store, "up-1", CS_B));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_change_in_flight_keeps_the_original_scope() {
    let up = tools_upstream().await;
    let (store, _d) =
        list_across_an_apply(&up, &[("a", "up-1", CS_A)], Some(&[("a", "up-2", CS_A)])).await;
    assert!(snapshot_in(&store, "up-1", CS_A));
    assert!(!snapshot_in(&store, "up-2", CS_A));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_removed_in_flight_keeps_the_original_scope() {
    let up = tools_upstream().await;
    // Revision 2 has no route `a`, only route `b` under another scope.
    let (store, _d) =
        list_across_an_apply(&up, &[("a", "up-1", CS_A)], Some(&[("b", "up-9", CS_B)])).await;
    assert!(snapshot_in(&store, "up-1", CS_A));
    assert!(!snapshot_in(&store, "up-9", CS_B));
}
