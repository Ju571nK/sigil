//! HTTPS+mTLS client wrapping `reqwest` with a rustls TLS config.
//!
//! Spec §3.8.2 — both endpoints share the same client cert.

use reqwest::{Client, ClientBuilder, Identity};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("read {path}: {source}")]
    Read { path: std::path::PathBuf, source: std::io::Error },
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
}
