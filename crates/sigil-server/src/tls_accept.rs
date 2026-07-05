//! #194 — peer-certificate identity plumbing for the mTLS listener.
//!
//! rustls verifies the client certificate chain during the TLS handshake
//! (`WebPkiClientVerifier`), but axum handlers never see WHO connected. This
//! module closes that gap:
//!
//! - [`PeerIdentity`] — leaf-cert fingerprint (blake3 of the DER) + subject CN
//!   + SAN DNS names, extracted once per connection after the handshake.
//! - [`PeerCertAcceptor`] — an [`axum_server::accept::Accept`] implementation
//!   that wraps axum-server's own `RustlsAcceptor` (same handshake, same
//!   timeout), then reads `peer_certificates()` off the resulting
//!   `tokio_rustls::server::TlsStream` and wraps the connection's service in
//!   [`InjectPeerIdentity`], which inserts `Arc<PeerIdentity>` into the
//!   extensions of every request on that connection.
//!
//! Handlers read it via `Option<Extension<Arc<PeerIdentity>>>`, so the plain
//! HTTP (no-mTLS dev) path — where the extension is simply absent — keeps
//! working unchanged.
//!
//! Security notes:
//! - The fingerprint is computed over the raw DER exactly as presented (and as
//!   verified by rustls); it needs no parsing and is therefore always set.
//! - CN/SAN parsing uses the pure-Rust `x509-parser` crate, which returns
//!   `Result` on malformed input (nom-based total parser — no panics on
//!   attacker-controlled bytes). Parse failure ⇒ `cn: None`, `san_dns: []`,
//!   fingerprint still set. In practice the leaf has already passed webpki
//!   chain verification before we ever parse it here.
//! - If rustls reports no peer certificate (defensive; `WebPkiClientVerifier`
//!   rejects anonymous clients during the handshake), NO extension is injected
//!   — handlers see `None`, never a forged identity.

use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

/// Identity of the TLS peer (client) on one connection, extracted from the
/// leaf certificate rustls verified during the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// blake3 hex (lowercase) of the leaf certificate DER bytes.
    pub fingerprint: String,
    /// Subject CN, if the certificate parses and carries one.
    pub cn: Option<String>,
    /// SAN DNS entries, if the certificate parses and carries any.
    pub san_dns: Vec<String>,
}

impl PeerIdentity {
    /// Build an identity from leaf-cert DER bytes. The fingerprint is always
    /// set (no parsing needed); CN/SAN fall back to `None`/empty when the
    /// certificate does not parse. Never panics on malformed input.
    pub fn from_der(der: &[u8]) -> Self {
        let fingerprint = blake3::hash(der).to_hex().to_string();
        let (cn, san_dns) = parse_cn_san(der).unwrap_or((None, Vec::new()));
        PeerIdentity {
            fingerprint,
            cn,
            san_dns,
        }
    }
}

/// Parse subject CN + SAN DNS names out of certificate DER. `None` when the
/// certificate itself does not parse; a malformed/absent SAN extension alone
/// degrades to an empty list (the CN is still returned).
fn parse_cn_san(der: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(str::to_owned);
    let san_dns = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some((*d).to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Some((cn, san_dns))
}

/// [`Accept`] implementation: run axum-server's rustls handshake, then expose
/// the verified peer identity to every request on the connection.
#[derive(Clone)]
pub struct PeerCertAcceptor {
    inner: RustlsAcceptor,
}

impl PeerCertAcceptor {
    pub fn new(config: RustlsConfig) -> Self {
        PeerCertAcceptor {
            inner: RustlsAcceptor::new(config),
        }
    }
}

impl<I, S> Accept<I, S> for PeerCertAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = InjectPeerIdentity<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            // Same handshake (and handshake timeout) as axum-server's own
            // rustls path — we only add identity extraction afterwards.
            let (stream, service) = inner.accept(stream, service).await?;
            let identity = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|leaf| Arc::new(PeerIdentity::from_der(leaf.as_ref())));
            Ok((
                stream,
                InjectPeerIdentity {
                    inner: service,
                    identity,
                },
            ))
        })
    }
}

/// Per-connection service wrapper that inserts `Arc<PeerIdentity>` into each
/// request's extensions. When the identity is absent (defensive: rustls
/// reported no peer cert), nothing is injected.
#[derive(Clone)]
pub struct InjectPeerIdentity<S> {
    inner: S,
    identity: Option<Arc<PeerIdentity>>,
}

impl<S, B> tower::Service<axum::http::Request<B>> for InjectPeerIdentity<S>
where
    S: tower::Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        if let Some(identity) = &self.identity {
            req.extensions_mut().insert(identity.clone());
        }
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn openssl() -> PathBuf {
        crate::enroll::sign::resolve_openssl().expect("openssl must be installed")
    }

    fn run(args: &[&std::ffi::OsStr]) {
        let o = Command::new(openssl()).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    /// Generate a self-signed cert (EC P-256, fast) with the given CN and
    /// optional SAN, and return its DER bytes.
    fn make_cert_der(dir: &Path, cn: &str, san: Option<&str>) -> Vec<u8> {
        let key = dir.join("k.pem");
        let crt = dir.join("c.pem");
        run(&[
            "genpkey".as_ref(),
            "-algorithm".as_ref(),
            "EC".as_ref(),
            "-pkeyopt".as_ref(),
            "ec_paramgen_curve:P-256".as_ref(),
            "-out".as_ref(),
            key.as_os_str(),
        ]);
        let subj = format!("/CN={cn}");
        let mut args: Vec<&std::ffi::OsStr> = vec![
            "req".as_ref(),
            "-x509".as_ref(),
            "-new".as_ref(),
            "-key".as_ref(),
            key.as_os_str(),
            "-days".as_ref(),
            "1".as_ref(),
            "-subj".as_ref(),
            subj.as_ref(),
        ];
        let san_ext = san.map(|s| format!("subjectAltName=DNS:{s}"));
        if let Some(ext) = san_ext.as_deref() {
            args.push("-addext".as_ref());
            args.push(ext.as_ref());
        }
        args.push("-out".as_ref());
        args.push(crt.as_os_str());
        run(&args);
        // PEM → DER via rustls-pemfile (same decoder the server uses).
        let pem = std::fs::read(&crt).unwrap();
        let mut rd = std::io::BufReader::new(&pem[..]);
        let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
            .collect::<Result<_, _>>()
            .unwrap();
        certs[0].as_ref().to_vec()
    }

    const HOST: &str = "018f9c1a-0000-7000-8000-0000000000aa";

    #[test]
    fn identity_from_cert_with_cn_and_san() {
        let d = tempfile::tempdir().unwrap();
        let der = make_cert_der(d.path(), HOST, Some(HOST));
        let id = PeerIdentity::from_der(&der);
        assert_eq!(id.fingerprint, blake3::hash(&der).to_hex().to_string());
        assert_eq!(id.cn.as_deref(), Some(HOST));
        assert_eq!(id.san_dns, vec![HOST.to_string()]);
    }

    #[test]
    fn identity_from_cert_without_san() {
        let d = tempfile::tempdir().unwrap();
        let der = make_cert_der(d.path(), "no-san-host", None);
        let id = PeerIdentity::from_der(&der);
        assert_eq!(id.cn.as_deref(), Some("no-san-host"));
        assert!(id.san_dns.is_empty());
    }

    /// Garbage DER: fingerprint is still set (it needs no parsing); CN/SAN
    /// degrade to None/empty. Must not panic.
    #[test]
    fn identity_from_garbage_der_keeps_fingerprint() {
        let garbage = b"definitely not a certificate";
        let id = PeerIdentity::from_der(garbage);
        assert_eq!(
            id.fingerprint,
            blake3::hash(garbage).to_hex().to_string(),
            "fingerprint must be blake3 of the raw bytes"
        );
        assert_eq!(id.cn, None);
        assert!(id.san_dns.is_empty());
    }

    /// The service wrapper injects `Arc<PeerIdentity>` into request extensions
    /// when an identity is present, and injects NOTHING when it is absent.
    #[tokio::test]
    async fn inject_service_adds_extension_only_when_identity_present() {
        use axum::http::Request;
        use tower::{Service, ServiceExt};

        // Echo service that reports whether the extension was present.
        let probe = tower::service_fn(|req: Request<axum::body::Body>| async move {
            let present = req.extensions().get::<Arc<PeerIdentity>>().is_some();
            Ok::<_, std::convert::Infallible>(axum::http::Response::new(present.to_string()))
        });

        let identity = Arc::new(PeerIdentity {
            fingerprint: "ff".into(),
            cn: Some("c".into()),
            san_dns: vec![],
        });
        let mut with_id = InjectPeerIdentity {
            inner: probe,
            identity: Some(identity),
        };
        let req = Request::builder().body(axum::body::Body::empty()).unwrap();
        let resp = with_id.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.into_body(), "true");

        let mut without_id = InjectPeerIdentity {
            inner: probe,
            identity: None,
        };
        let req = Request::builder().body(axum::body::Body::empty()).unwrap();
        let resp = without_id.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.into_body(), "false");
    }
}
