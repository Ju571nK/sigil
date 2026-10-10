//! T-01 throwaway probe for rmcp 0.16.0 (2026-10-10). Not production code.
//!
//! Subcommands:
//!   serde                  typed round-trip of raw JSON-RPC messages (no network)
//!   client <url> [token]   rmcp Streamable HTTP client against a fixture
//!   server                 rmcp Streamable HTTP server on 127.0.0.1:0 (prints listen line)

use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResult, ClientJsonRpcMessage, ClientRequest,
    Content, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo,
    ServerJsonRpcMessage, ServerResult, Tool,
};
use rmcp::service::{PeerRequestOptions, RequestContext};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Value};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serde") => serde_probe(),
        Some("client") => client_probe(&args[2], args.get(3).cloned()).await,
        Some("server") => server_probe().await,
        _ => eprintln!("usage: rmcp-sdk-probe serde | client <url> [bearer-file] | server"),
    }
}

/// Parse with the typed rmcp message enum, re-serialise, and diff top-level keys.
fn roundtrip<T: serde::de::DeserializeOwned + serde::Serialize>(label: &str, input: Value) -> Value {
    match serde_json::from_value::<T>(input.clone()) {
        Err(e) => json!({"case": label, "parsed": false, "error": e.to_string()}),
        Ok(typed) => {
            let out = serde_json::to_value(&typed).unwrap();
            json!({
                "case": label,
                "parsed": true,
                "identical": out == input,
                "lost_paths": diff(&input, &out, ""),
                "added_paths": diff(&out, &input, ""),
                "output": out,
            })
        }
    }
}

/// Paths present (with a value) in `a` but missing/different in `b`.
fn diff(a: &Value, b: &Value, path: &str) -> Vec<String> {
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => ma
            .iter()
            .flat_map(|(k, va)| {
                let p = format!("{path}/{k}");
                match mb.get(k) {
                    None => vec![p],
                    Some(vb) => diff(va, vb, &p),
                }
            })
            .collect(),
        (Value::Array(xa), Value::Array(xb)) => xa
            .iter()
            .enumerate()
            .flat_map(|(i, va)| match xb.get(i) {
                None => vec![format!("{path}/{i}")],
                Some(vb) => diff(va, vb, &format!("{path}/{i}")),
            })
            .collect(),
        _ if a == b => vec![],
        _ => vec![format!("{path} (value changed)")],
    }
}

fn serde_probe() {
    let init = |v: &str| {
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion": v, "capabilities": {}, "clientInfo": {"name":"p","version":"0"}}})
    };
    let mut cases = vec![];
    for v in ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "1999-01-01", "not-a-version"] {
        cases.push(roundtrip::<ClientJsonRpcMessage>(&format!("initialize protocolVersion={v}"), init(v)));
    }
    cases.push(roundtrip::<ClientJsonRpcMessage>(
        "tools/call request with unknown fields (params, envelope, _meta)",
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call","x-envelope-unknown":1,"params":{
            "name":"json_ok","arguments":{},"x-param-unknown":{"a":1},
            "_meta":{"progressToken":"p1","x-meta-unknown":true}}}),
    ));
    cases.push(roundtrip::<ServerJsonRpcMessage>(
        "tools/call result with unknown fields (result, content item, _meta, envelope)",
        json!({"jsonrpc":"2.0","id":7,"x-envelope-unknown":1,"result":{
            "content":[{"type":"text","text":"hi","x-content-unknown":1}],
            "structuredContent":{"k":"v"},"isError":false,
            "x-result-unknown":{"b":2},"_meta":{"x-meta-unknown":true}}}),
    ));
    cases.push(roundtrip::<ServerJsonRpcMessage>(
        "initialize result with 2025-11-25 and unknown capability",
        json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25",
            "capabilities":{"tools":{"listChanged":false},"x-cap-unknown":{}},
            "serverInfo":{"name":"s","version":"1","x-info-unknown":1}}}),
    ));
    cases.push(roundtrip::<ServerJsonRpcMessage>(
        "tools/list result with unknown tool fields",
        json!({"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"t","inputSchema":{"type":"object"},
            "x-tool-unknown":1}],"nextCursor":"page-2"}}),
    ));
    cases.push(roundtrip::<ClientJsonRpcMessage>(
        "notifications/cancelled",
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"user"}}),
    ));
    cases.push(roundtrip::<ClientJsonRpcMessage>(
        "unknown client request method",
        json!({"jsonrpc":"2.0","id":9,"method":"x-vendor/thing","params":{"a":1}}),
    ));
    cases.push(roundtrip::<ClientJsonRpcMessage>(
        "batch array (removed in 2025-06-18)",
        json!([{"jsonrpc":"2.0","id":1,"method":"ping"}]),
    ));
    println!("{}", serde_json::to_string_pretty(&json!({"rmcp":"0.16.0","cases":cases})).unwrap());
}

async fn client_probe(url: &str, bearer_file: Option<String>) {
    let mut cfg = StreamableHttpClientTransportConfig::with_uri(url.to_string());
    if let Some(f) = bearer_file {
        cfg = cfg.auth_header(std::fs::read_to_string(f).unwrap().trim().to_string());
    }
    let transport = StreamableHttpClientTransport::from_config(cfg);
    let mut report = serde_json::Map::new();
    let client = match ().serve(transport).await {
        Ok(c) => c,
        Err(e) => {
            println!("{}", json!({"initialize_error": e.to_string()}));
            return;
        }
    };
    let info = client.peer_info().cloned();
    report.insert("server_initialize_result".into(), serde_json::to_value(&info).unwrap());
    report.insert("client_offered_protocol_version".into(), json!(rmcp::model::ProtocolVersion::LATEST.to_string()));
    report.insert(
        "list_all_tools".into(),
        match client.list_all_tools().await {
            Ok(t) => json!(t.iter().map(|t| t.name.to_string()).collect::<Vec<_>>()),
            Err(e) => json!({"error": e.to_string()}),
        },
    );
    for name in ["json_ok", "sse_ok", "tool_error", "drop_after_accept"] {
        let params: CallToolRequestParams =
            serde_json::from_value(json!({"name": name, "arguments": {}})).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(10), client.call_tool(params)).await;
        let v = match r {
            Err(_) => json!({"outcome": "probe timeout 10s"}),
            Ok(Ok(res)) => json!({"outcome": "result", "result": res}),
            Ok(Err(e)) => json!({"outcome": "error", "error": e.to_string()}),
        };
        report.insert(format!("call {name}"), v);
    }
    // Cancellation: rmcp sends notifications/cancelled itself when a per-request timeout fires.
    let params: CallToolRequestParams =
        serde_json::from_value(json!({"name": "slow_ok", "arguments": {}})).unwrap();
    let req = ClientRequest::CallToolRequest(CallToolRequest::new(params));
    let opts = PeerRequestOptions { timeout: Some(Duration::from_secs(2)), meta: None };
    let v = match client.send_request_with_option(req, opts).await {
        Err(e) => json!({"send_error": e.to_string()}),
        Ok(handle) => match handle.await_response().await {
            Ok(r) => json!({"outcome": "result", "result": r}),
            Err(e) => json!({"outcome": "error", "error": e.to_string()}),
        },
    };
    report.insert("call slow_ok with 2s rmcp timeout".into(), v);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = client.cancel().await;
    println!("{}", serde_json::to_string_pretty(&Value::Object(report)).unwrap());
}

#[derive(Clone)]
struct EchoServer;

impl ServerHandler for EchoServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
    async fn list_tools(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tool: Tool = serde_json::from_value(json!({"name":"echo_params",
            "inputSchema":{"type":"object"}})).unwrap();
        Ok(ListToolsResult { tools: vec![tool], ..Default::default() })
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // Echo what the typed handler actually received.
        let seen = serde_json::to_string(&request).unwrap();
        Ok(CallToolResult::success(vec![Content::text(seen)]))
    }
}

async fn server_probe() {
    let service = StreamableHttpService::new(
        || Ok(EchoServer),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!("{}", json!({"listen": listener.local_addr().unwrap().to_string()}));
    let _ = ServerResult::empty(()); // keep import set stable across rmcp patch versions
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let svc = hyper_util::service::TowerToHyperService::new(service.clone());
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });
    }
}
