//! HTTPS+mTLS client wrapping `reqwest` with a rustls TLS config.
//!
//! Spec §3.8.2 — both endpoints share the same client cert.

use reqwest::{Client, ClientBuilder, Identity};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("read {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("invalid identity (cert+key): {0}")]
    Identity(reqwest::Error),
    #[error("invalid root CA bundle")]
    InvalidCa,
    #[error("client build: {0}")]
    Build(reqwest::Error),
}

/// Build a reqwest client preconfigured with mTLS using the supplied
/// PEM-encoded client cert chain + private key, validating server certs
/// against the supplied PEM-encoded CA bundle.
pub fn build_client(
    client_cert_pem: &Path,
    client_key_pem: &Path,
    server_ca_pem: &Path,
) -> Result<Client, TransportError> {
    let cert_pem = std::fs::read(client_cert_pem).map_err(|source| TransportError::Read {
        path: client_cert_pem.to_path_buf(),
        source,
    })?;
    let key_pem = std::fs::read(client_key_pem).map_err(|source| TransportError::Read {
        path: client_key_pem.to_path_buf(),
        source,
    })?;
    let mut combined = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
    combined.extend_from_slice(&cert_pem);
    combined.push(b'\n');
    combined.extend_from_slice(&key_pem);
    let identity = Identity::from_pem(&combined).map_err(TransportError::Identity)?;

    let ca_pem = std::fs::read(server_ca_pem).map_err(|source| TransportError::Read {
        path: server_ca_pem.to_path_buf(),
        source,
    })?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).map_err(|_| TransportError::InvalidCa)?;

    ClientBuilder::new()
        .use_rustls_tls()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .tls_built_in_root_certs(false)
        .build()
        .map_err(TransportError::Build)
}

/// High-level outcome of an HTTP send. The data_task uses this to decide
/// retry vs. permanent-pause vs. event emission.
#[derive(Debug)]
pub enum SendOutcome<R> {
    /// 2xx with parsed body.
    Ok2xx(R),
    /// 4xx with a documented "permanent" status (409, 426). data_task pauses.
    PermanentReject { status: u16, body: String },
    /// 5xx (any) — retryable with backoff.
    ServerBusy { status: u16, body: String },
    /// TLS handshake failed — typically cert expired or CA mismatch.
    TlsFailure(String),
    /// Network failure (DNS, connect, timeout) — retry.
    Network(String),
    /// Unparseable body or other unexpected protocol issue.
    ProtocolViolation(String),
}

/// Classify a `reqwest::Error` (or status) into a `SendOutcome`. Caller
/// passes the raw response status + body for status-based mapping.
pub fn classify_status<R>(status: u16, body: String, parsed: Option<R>) -> SendOutcome<R> {
    if (200..300).contains(&status) {
        match parsed {
            Some(r) => SendOutcome::Ok2xx(r),
            None => SendOutcome::ProtocolViolation(format!("2xx without parseable body: {body}")),
        }
    } else if status == 409 || status == 426 {
        SendOutcome::PermanentReject { status, body }
    } else if (500..600).contains(&status) || status == 503 {
        SendOutcome::ServerBusy { status, body }
    } else {
        SendOutcome::ProtocolViolation(format!("unexpected status {status}: {body}"))
    }
}

/// Maps a `reqwest::Error` from the *send/connect* phase (no HTTP status
/// available) to either a TLS or network failure.
pub fn classify_send_error<R>(err: reqwest::Error) -> SendOutcome<R> {
    let msg = err.to_string();
    if msg.contains("tls") || msg.contains("certificate") || msg.contains("handshake") {
        SendOutcome::TlsFailure(msg)
    } else {
        SendOutcome::Network(msg)
    }
}

/// Returns `Some(latest_mtime)` if any of the cert / key / CA files have
/// changed since `since`; otherwise `None`. Used by the supervisor to
/// rebuild the client on cert rotation.
pub fn newest_pem_mtime(paths: &[&Path]) -> std::io::Result<Option<std::time::SystemTime>> {
    let mut newest: Option<std::time::SystemTime> = None;
    for p in paths {
        let m = std::fs::metadata(p)?.modified()?;
        newest = Some(match newest {
            Some(prev) if prev >= m => prev,
            _ => m,
        });
    }
    Ok(newest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_cert_returns_read_error() {
        let dir = tempdir().unwrap();
        let err = build_client(
            &dir.path().join("missing.crt"),
            &dir.path().join("missing.key"),
            &dir.path().join("missing-ca.pem"),
        )
        .unwrap_err();
        assert!(matches!(err, TransportError::Read { .. }));
    }

    #[test]
    fn malformed_pem_returns_identity_error() {
        let dir = tempdir().unwrap();
        let cert = dir.path().join("c.crt");
        let key = dir.path().join("c.key");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&cert, b"not a pem").unwrap();
        std::fs::write(&key, b"not a pem either").unwrap();
        std::fs::write(&ca, b"definitely not pem").unwrap();
        let err = build_client(&cert, &key, &ca).unwrap_err();
        assert!(matches!(err, TransportError::Identity(_)));
    }

    #[test]
    fn newest_mtime_picks_max() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, b"1").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&b, b"2").unwrap();
        let m = newest_pem_mtime(&[&a, &b]).unwrap().unwrap();
        let m_b = std::fs::metadata(&b).unwrap().modified().unwrap();
        assert_eq!(m, m_b);
    }

    #[test]
    fn classify_2xx_returns_ok() {
        let outcome: SendOutcome<()> = classify_status(200, "{}".into(), Some(()));
        assert!(matches!(outcome, SendOutcome::Ok2xx(())));
    }

    #[test]
    fn classify_409_is_permanent() {
        let outcome: SendOutcome<()> = classify_status(409, "conflict".into(), None);
        assert!(matches!(
            outcome,
            SendOutcome::PermanentReject { status: 409, .. }
        ));
    }

    #[test]
    fn classify_426_is_permanent() {
        let outcome: SendOutcome<()> = classify_status(426, "upgrade".into(), None);
        assert!(matches!(
            outcome,
            SendOutcome::PermanentReject { status: 426, .. }
        ));
    }

    #[test]
    fn classify_503_is_server_busy() {
        let outcome: SendOutcome<()> = classify_status(503, "busy".into(), None);
        assert!(matches!(
            outcome,
            SendOutcome::ServerBusy { status: 503, .. }
        ));
    }

    #[test]
    fn classify_2xx_without_body_is_protocol_violation() {
        let outcome: SendOutcome<()> = classify_status(200, "".into(), None);
        assert!(matches!(outcome, SendOutcome::ProtocolViolation(_)));
    }
}
