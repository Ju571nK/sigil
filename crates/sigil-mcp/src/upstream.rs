use crate::config::Config;
use reqwest::{Client, ClientBuilder, Identity, StatusCode};
use rmcp::ErrorData as McpError;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("authentication failed (HTTP {0}); check SIGIL_SERVER_READ_TOKEN")]
    Auth(u16),
    #[error(
        "not found (HTTP 404): read API may be disabled (no server read token) or the id is unknown"
    )]
    NotFound,
    #[error("invalid query (HTTP 400): {0}")]
    BadQuery(String),
    #[error("upstream sigil-server error (HTTP {0}): {1}")]
    Server(u16, String),
    #[error("cannot reach sigil-server at {0}: {1}")]
    Connection(String, String),
    #[error("client build failed: {0}")]
    Build(String),
    #[error("unexpected response: {0}")]
    Protocol(String),
}

impl From<UpstreamError> for McpError {
    fn from(e: UpstreamError) -> Self {
        match &e {
            // A 400 means the tool built a bad query param — caller-facing.
            UpstreamError::BadQuery(_) => McpError::invalid_params(e.to_string(), None),
            // Auth/connection/server/etc. are server-side/config issues, not bad tool args.
            _ => McpError::internal_error(e.to_string(), None),
        }
    }
}

// fields and methods used by tool layer in Task 4
#[allow(dead_code)]
#[derive(Clone)]
pub struct Upstream {
    client: Client,
    base_url: String,
    token: String,
}

impl Upstream {
    // used by main.rs in Task 4
    #[allow(dead_code)]
    pub fn new(cfg: &Config) -> Result<Self, UpstreamError> {
        let client = match &cfg.mtls {
            Some(m) => build_mtls_client(&m.client_cert, &m.client_key, &m.ca_cert)?,
            None => Client::new(),
        };
        Ok(Upstream {
            client,
            base_url: cfg.base_url.clone(),
            token: cfg.token.clone(),
        })
    }

    #[cfg(test)]
    pub fn for_test(base_url: String) -> Self {
        Upstream {
            client: Client::new(),
            base_url,
            token: "testtoken".to_string(),
        }
    }

    /// GET `path` (+optional query), return parsed JSON. Only verb used: GET.
    // used by tool layer in Task 4
    #[allow(dead_code)]
    pub async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, UpstreamError> {
        debug_assert!(path.starts_with('/'), "path must start with '/': {path}");
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.get(&url).bearer_auth(&self.token);
        if !query.is_empty() {
            req = req.query(query);
        }
        let resp = req
            .send()
            .await
            .map_err(|err| UpstreamError::Connection(self.base_url.clone(), err.to_string()))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        match status {
            s if s.is_success() => serde_json::from_str(&body)
                .map_err(|e| UpstreamError::Protocol(format!("non-JSON 2xx body: {e}"))),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(UpstreamError::Auth(status.as_u16()))
            }
            StatusCode::NOT_FOUND => Err(UpstreamError::NotFound),
            StatusCode::BAD_REQUEST => Err(UpstreamError::BadQuery(body)),
            s if s.is_server_error() => Err(UpstreamError::Server(s.as_u16(), body)),
            s => Err(UpstreamError::Protocol(format!(
                "unexpected HTTP {s}: {body}"
            ))),
        }
    }
}

fn build_mtls_client(cert: &Path, key: &Path, ca: &Path) -> Result<Client, UpstreamError> {
    let cert_pem = std::fs::read(cert).map_err(|e| UpstreamError::Build(e.to_string()))?;
    let key_pem = std::fs::read(key).map_err(|e| UpstreamError::Build(e.to_string()))?;
    let mut combined = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
    combined.extend_from_slice(&cert_pem);
    combined.push(b'\n');
    combined.extend_from_slice(&key_pem);
    let identity =
        Identity::from_pem(&combined).map_err(|e| UpstreamError::Build(e.to_string()))?;
    let ca_pem = std::fs::read(ca).map_err(|e| UpstreamError::Build(e.to_string()))?;
    let ca_cert =
        reqwest::Certificate::from_pem(&ca_pem).map_err(|e| UpstreamError::Build(e.to_string()))?;
    ClientBuilder::new()
        .use_rustls_tls()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .tls_built_in_root_certs(false)
        .build()
        .map_err(|e| UpstreamError::Build(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::{Method::GET, MockServer};
    use serde_json::json;

    #[tokio::test]
    async fn get_200_returns_json_and_sends_bearer() {
        let server = MockServer::start_async().await;
        let m = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/v1/fleet/risk")
                    .header("authorization", "Bearer testtoken");
                then.status(200).json_body(json!({"hosts": []}));
            })
            .await;

        let up = Upstream::for_test(server.base_url());
        let v = up.get("/v1/fleet/risk", &[]).await.unwrap();

        m.assert_async().await;
        assert_eq!(v, json!({"hosts": []}));
    }

    #[tokio::test]
    async fn query_params_are_sent() {
        let server = MockServer::start_async().await;
        let m = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/v1/events")
                    .query_param("limit", "100")
                    .query_param("host_id", "H1");
                then.status(200)
                    .json_body(json!({"events": [], "next_cursor": null}));
            })
            .await;

        let up = Upstream::for_test(server.base_url());
        let q = vec![("host_id", "H1".to_string()), ("limit", "100".to_string())];
        up.get("/v1/events", &q).await.unwrap();

        m.assert_async().await;
    }

    #[tokio::test]
    async fn status_401_maps_to_auth() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/meta");
                then.status(401);
            })
            .await;
        let up = Upstream::for_test(server.base_url());
        assert!(matches!(
            up.get("/v1/meta", &[]).await,
            Err(UpstreamError::Auth(401))
        ));
    }

    #[tokio::test]
    async fn status_403_maps_to_auth() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/meta");
                then.status(403);
            })
            .await;
        let up = Upstream::for_test(server.base_url());
        assert!(matches!(
            up.get("/v1/meta", &[]).await,
            Err(UpstreamError::Auth(403))
        ));
    }

    #[tokio::test]
    async fn status_404_maps_to_not_found() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/fleet/hosts/x");
                then.status(404);
            })
            .await;
        let up = Upstream::for_test(server.base_url());
        assert!(matches!(
            up.get("/v1/fleet/hosts/x", &[]).await,
            Err(UpstreamError::NotFound)
        ));
    }

    #[tokio::test]
    async fn status_400_carries_body() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/events");
                then.status(400).body("cursor must be a UUID");
            })
            .await;
        let up = Upstream::for_test(server.base_url());
        match up.get("/v1/events", &[]).await {
            Err(UpstreamError::BadQuery(b)) => assert!(b.contains("UUID")),
            other => panic!("expected BadQuery, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn status_503_maps_to_server() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/fleet/risk");
                then.status(503).body("busy");
            })
            .await;
        let up = Upstream::for_test(server.base_url());
        assert!(matches!(
            up.get("/v1/fleet/risk", &[]).await,
            Err(UpstreamError::Server(503, _))
        ));
    }

    #[tokio::test]
    async fn success_with_non_json_body_maps_to_protocol() {
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/healthz");
                then.status(200).body("ok");
            })
            .await;
        let up = Upstream::for_test(server.base_url());
        assert!(matches!(
            up.get("/v1/healthz", &[]).await,
            Err(UpstreamError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn connection_refused_maps_to_connection() {
        // Nothing listening on this port.
        let up = Upstream::for_test("http://127.0.0.1:1".to_string());
        assert!(matches!(
            up.get("/v1/healthz", &[]).await,
            Err(UpstreamError::Connection(_, _))
        ));
    }
}
