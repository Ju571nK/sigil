#![cfg(unix)]
//! T-12b2: runtime route health over HTTP, on a route with an applied scope.
//!
//! * An `initialize` answered outside the allowlist marks the binding
//!   `unsupported`; the next `initialize` on it is refused locally (same fixed
//!   -32603, never sent, no reason) until the route is repointed.
//! * A task handle marks the route `degraded`, which never refuses an
//!   `initialize`.

mod common;
use common::*;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sigil_proxy::bootstrap::Credential;
use sigil_proxy::dest::SystemResolver;
use sigil_proxy::mcp::observation::{
    Cause, Completed, Delivery, Method, Observation, ObservationSink, Outcome, RequestStarted,
    SinkFuture, StartVerdict,
};
use sigil_proxy::route::{PrincipalSpec, RouteScope, RouteSpec, RouteTable, TableHandle};
use sigil_proxy::server::Proxy;
use sigil_proxy_api::status::{RouteReason, RouteState};
use sigil_proxy_api::Id;
use tokio::sync::oneshot;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(20);

#[derive(Default)]
struct Rec(Mutex<Vec<Completed>>);

impl ObservationSink for Rec {
    fn request_started<'a>(&'a self, _: &'a RequestStarted) -> SinkFuture<'a, StartVerdict> {
        Box::pin(async { StartVerdict::Proceed })
    }
    fn observe(&self, o: Observation) {
        if let Observation::Completed(c) = o {
            self.0.lock().unwrap().push(c);
        }
    }
}

/// Route `a` on `up` with an applied scope (upstream `up-1`), principal `p`/`t`.
fn scoped(dir: &std::path::Path, up: &Up) -> RouteTable {
    let secret = dir.join("secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let creds = BTreeMap::from([(
        "up".to_string(),
        Credential {
            secret_file: secret,
            upstream_origins: vec![format!("http://127.0.0.1:{}", up.addr.port())],
        },
    )]);
    RouteTable::build(
        &[RouteSpec {
            route_id: Id::new("a").unwrap(),
            upstream_url: up.url("/mcp"),
            credential_ref: "up".into(),
            principals: vec![PrincipalSpec::new(
                Id::new("p").unwrap(),
                vec![sigil_proxy_api::verifier_for("t").into()],
            )],
            allowed_origins: vec![],
            allow_private_destination: false,
            limits: Default::default(),
            scope: Some(RouteScope {
                upstream_id: "up-1".into(),
                credential_scope_id: "cs-1".into(),
            }),
        }],
        &creds,
        &limits(),
    )
    .unwrap()
}

struct Run {
    addr: std::net::SocketAddr,
    handle: TableHandle,
    proxy_health: sigil_proxy::route_health::RouteHealth,
    rec: Arc<Rec>,
    stop: Option<oneshot::Sender<()>>,
}

async fn run(table: RouteTable) -> Run {
    let handle = TableHandle::new();
    handle.set(Some(table));
    let rec = Arc::new(Rec::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Proxy::new(limits(), handle.clone(), Arc::new(SystemResolver)).with_sink(
        rec.clone() as Arc<dyn ObservationSink>,
        sigil_proxy::inventory::CursorHasher::new().unwrap(),
    );
    let proxy_health = proxy.route_health();
    let (stop, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = proxy
            .serve(listener, None, async {
                let _ = rx.await;
            })
            .await;
    });
    Run {
        addr,
        handle,
        proxy_health,
        rec,
        stop: Some(stop),
    }
}

impl Run {
    async fn post(&self, body: &[u8], session: Option<&str>) -> Raw {
        let mut req = format!(
            "POST /mcp/a HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             Authorization: Bearer t\r\nContent-Type: application/json\r\n\
             Accept: application/json, text/event-stream\r\n{}{}\
             Content-Length: {}\r\n\r\n",
            self.addr,
            session
                .map(|s| format!("Mcp-Session-Id: {s}\r\n"))
                .unwrap_or_default(),
            if session.is_some() {
                "MCP-Protocol-Version: 2025-11-25\r\n"
            } else {
                ""
            },
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(body);
        timeout(WAIT, send_raw(self.addr, &req))
            .await
            .expect("answered")
    }

    fn inits(&self) -> Vec<Completed> {
        self.rec
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.method == Method::Initialize)
            .cloned()
            .collect()
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

fn refusal() -> Value {
    json!({"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error"}})
}

#[tokio::test]
async fn an_unsupported_binding_refuses_the_next_initialize_locally_until_repointed() {
    let old = Up::start_raw(|s| {
        let id = initialize_id(&s.body).unwrap_or(Value::Null);
        full(
            200,
            "application/json",
            json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18","capabilities":{}}})
                .to_string()
                .as_bytes(),
        )
    })
    .await;
    let d = tempfile::tempdir().unwrap();
    let px = run(scoped(d.path(), &old)).await;

    let first = px.post(initialize_body("1").as_bytes(), None).await;
    assert_eq!(first.status, 200);
    assert!(!first.has("mcp-session-id"));
    assert_eq!(
        serde_json::from_slice::<Value>(&first.body()).unwrap(),
        refusal()
    );
    assert_eq!(old.count(), 1);
    let marks = px.proxy_health.current();
    assert_eq!(marks["up-1"].state, RouteState::Unsupported);
    assert_eq!(
        marks["up-1"].reason,
        RouteReason::UpstreamVersionUnsupported
    );

    // The same answer, without contacting the upstream.
    let second = px.post(initialize_body("1").as_bytes(), None).await;
    assert_eq!(second.status, 200);
    assert!(!second.has("mcp-session-id"));
    assert_eq!(second.body(), first.body());
    assert_eq!(old.count(), 1, "refused before the upstream");
    let inits = px.inits();
    assert_eq!(inits.len(), 2);
    assert_eq!(
        (inits[0].outcome, inits[0].delivery, inits[0].cause),
        (
            Outcome::ProtocolError,
            Delivery::Sent,
            Cause::UpstreamVersionUnsupported
        )
    );
    assert_eq!(
        (inits[1].outcome, inits[1].delivery, inits[1].cause),
        (
            Outcome::ProtocolError,
            Delivery::NotSent,
            Cause::RouteUnsupported
        )
    );

    // A repoint to another endpoint is a new binding: judged afresh.
    let new = Up::start(|_| full(200, "application/json", b"{}")).await;
    let d2 = tempfile::tempdir().unwrap();
    px.handle.set(Some(scoped(d2.path(), &new)));
    let third = px.post(initialize_body("1").as_bytes(), None).await;
    assert_eq!(third.status, 200);
    assert!(third.has("mcp-session-id"));
    assert_eq!(old.count(), 1);
    assert!(px.proxy_health.current().is_empty());
}

#[tokio::test]
async fn a_degraded_route_still_initializes() {
    let up = Up::start(|s| {
        let v: Value = serde_json::from_slice(&s.body).unwrap();
        full(
            200,
            "application/json",
            json!({"jsonrpc":"2.0","id":v["id"],"result":{"task":{"taskId":"t-1","status":"working"}}})
                .to_string()
                .as_bytes(),
        )
    })
    .await;
    let d = tempfile::tempdir().unwrap();
    let px = run(scoped(d.path(), &up)).await;
    let init = px.post(initialize_body("1").as_bytes(), None).await;
    let sid = init.header("mcp-session-id").expect("session").to_string();
    let call = px
        .post(
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x"}}"#,
            Some(&sid),
        )
        .await;
    assert_eq!(call.status, 200, "the task handle is relayed unchanged");
    let marks = px.proxy_health.current();
    assert_eq!(marks["up-1"].state, RouteState::Degraded);
    assert_eq!(
        marks["up-1"].reason,
        RouteReason::TaskAugmentationUnsupported
    );
    let again = px.post(initialize_body("3").as_bytes(), None).await;
    assert!(
        again.has("mcp-session-id"),
        "degraded never refuses an initialize"
    );
}
