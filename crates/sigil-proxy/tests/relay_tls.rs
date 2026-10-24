#![cfg(unix)]
//! Listener TLS (non-loopback binds require it; PX-008/014). Uses the `openssl`
//! CLI to mint a throwaway self-signed certificate; the test is skipped (and
//! says so) when the CLI is absent.

mod common;
use common::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The listener serves HTTP/1.1 over TLS, the bearer rules still apply, and the
/// relay works through it. Plain-text clients get no HTTP answer.
#[tokio::test]
async fn tls_listener_relays() {
    let dir = tempfile::tempdir().unwrap();
    let (c, k) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    // A CA plus a CA-signed leaf (RSA, fixed serials): the profile webpki
    // accepts across OpenSSL and LibreSSL. A self-signed leaf used as its own
    // trust anchor is rejected by some LibreSSL builds' extension output.
    let ca = dir.path().join("ca.pem");
    let ca_key = dir.path().join("ca.key");
    let csr = dir.path().join("c.csr");
    let ext = dir.path().join("c.ext");
    std::fs::write(
        &ext,
        "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
    )
    .unwrap();
    let steps: [Vec<&std::ffi::OsStr>; 4] = [
        vec![
            "genpkey".as_ref(),
            "-algorithm".as_ref(),
            "RSA".as_ref(),
            "-pkeyopt".as_ref(),
            "rsa_keygen_bits:2048".as_ref(),
            "-out".as_ref(),
            ca_key.as_os_str(),
        ],
        vec![
            "req".as_ref(),
            "-x509".as_ref(),
            "-new".as_ref(),
            "-key".as_ref(),
            ca_key.as_os_str(),
            "-days".as_ref(),
            "2".as_ref(),
            "-set_serial".as_ref(),
            "1".as_ref(),
            "-subj".as_ref(),
            "/CN=relay-tls-test-ca".as_ref(),
            "-addext".as_ref(),
            "basicConstraints=critical,CA:TRUE".as_ref(),
            "-out".as_ref(),
            ca.as_os_str(),
        ],
        vec![
            "req".as_ref(),
            "-new".as_ref(),
            "-newkey".as_ref(),
            "rsa:2048".as_ref(),
            "-nodes".as_ref(),
            "-keyout".as_ref(),
            k.as_os_str(),
            "-subj".as_ref(),
            "/CN=localhost".as_ref(),
            "-out".as_ref(),
            csr.as_os_str(),
        ],
        vec![
            "x509".as_ref(),
            "-req".as_ref(),
            "-in".as_ref(),
            csr.as_os_str(),
            "-CA".as_ref(),
            ca.as_os_str(),
            "-CAkey".as_ref(),
            ca_key.as_os_str(),
            "-set_serial".as_ref(),
            "2".as_ref(),
            "-days".as_ref(),
            "2".as_ref(),
            "-extfile".as_ref(),
            ext.as_os_str(),
            "-out".as_ref(),
            c.as_os_str(),
        ],
    ];
    // Same probe order as the server e2e tests (proven on the macOS runner,
    // whose PATH openssl emits certificates webpki rejects).
    let openssl = [
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
    ]
    .into_iter()
    .map(std::path::PathBuf::from)
    .find(|p| p.is_file())
    .unwrap_or_else(|| "openssl".into());
    for args in &steps {
        let Ok(out) = std::process::Command::new(&openssl)
            .env_remove("OPENSSL_CONF")
            .args(args)
            .output()
        else {
            eprintln!("SKIPPED: openssl CLI not available");
            return;
        };
        assert!(
            out.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();

    let acceptor = sigil_proxy::tls::load_acceptor(&c, &k).unwrap();
    let up = ok_upstream().await;
    let l = limits();
    let t = table(&[R::new("a", up.url("/up"), &[("pa", "tok-a")])], &l);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = sigil_proxy::route::TableHandle::new();
    handle.set(Some(t));
    let proxy =
        sigil_proxy::server::Proxy::new(l, handle, Arc::new(sigil_proxy::dest::SystemResolver));
    let task = tokio::spawn(async move {
        proxy
            .serve(listener, Some(acceptor), std::future::pending())
            .await
    });

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&ca).unwrap();
    for cert in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(cert.unwrap()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let conn = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let exchange = |token: &'static str, lines: String, body: String| {
        let conn = conn.clone();
        async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut s = conn
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    tcp,
                )
                .await
                .unwrap();
            let req = format!(
                "POST /mcp/a HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n{lines}Content-Length: {}\r\n\r\n{body}",
                addr.port(),
                body.len()
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            parse_response(buf)
        }
    };
    // initialize, then a call inside the proxy session
    let init = exchange("tok-a", String::new(), initialize_body("0")).await;
    assert_eq!(init.status, 200);
    let sid = init
        .header("mcp-session-id")
        .expect("a proxy session")
        .to_string();
    let lines = format!("Mcp-Session-Id: {sid}\r\nMCP-Protocol-Version: 2025-11-25\r\n");
    let ping = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string();
    assert_eq!(
        exchange("tok-a", lines.clone(), ping.clone()).await.status,
        200
    );
    assert_eq!(exchange("wrong", lines, ping).await.status, 401);
    assert_eq!(up.count(), 1);

    // plain text to the TLS port never yields an HTTP response
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = s
        .write_all(b"POST /mcp/a HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    let mut b = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), s.read_to_end(&mut b)).await;
    assert!(!b.starts_with(b"HTTP/1.1"));
    task.abort();
}
