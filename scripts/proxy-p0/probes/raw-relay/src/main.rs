//! Throwaway probe: byte-preserving HTTP/1.1 reverse relay (no retries, no synthesized errors).
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderValue, HOST};
use hyper::service::service_fn;
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

type Err = Box<dyn std::error::Error + Send + Sync>;
type Out = BoxBody<Bytes, hyper::Error>;

struct Cfg {
    authority: String,
    capture: Option<PathBuf>,
    counter: AtomicUsize,
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection" | "keep-alive" | "te" | "trailer" | "transfer-encoding" | "upgrade"
    ) || name.starts_with("proxy-")
}

fn filtered(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in src {
        if !hop_by_hop(k.as_str()) {
            out.append(k.clone(), v.clone());
        }
    }
    out
}

/// Stream the body through unchanged, copying each data frame to `file` as it passes.
fn tee(body: Incoming, file: Option<File>) -> Out {
    match file {
        None => body.boxed(),
        Some(mut f) => body
            .map_frame(move |frame| {
                if let Some(d) = frame.data_ref() {
                    let _ = f.write_all(d);
                }
                frame
            })
            .boxed(),
    }
}

fn capture_file(cfg: &Cfg, n: usize, kind: &str) -> Option<File> {
    let dir = cfg.capture.as_ref()?;
    File::create(dir.join(format!("{n}.{kind}.bin"))).ok()
}

async fn relay(req: Request<Incoming>, cfg: Arc<Cfg>) -> Result<Response<Out>, Err> {
    let n = cfg.counter.fetch_add(1, Ordering::SeqCst) + 1;
    let closed = || eprintln!("{{\"event\":\"upstream_closed_before_headers\"}}");
    let (parts, body) = req.into_parts();
    eprintln!("{{\"event\":\"host_rewritten\",\"n\":{n}}}");

    let mut up_req = Request::new(tee(body, capture_file(&cfg, n, "req")));
    *up_req.method_mut() = parts.method;
    *up_req.uri_mut() = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .parse::<Uri>()?;
    *up_req.headers_mut() = filtered(&parts.headers);
    up_req
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(&cfg.authority)?);

    // One fresh upstream connection per exchange; nothing is ever re-sent.
    let stream = match TcpStream::connect(&cfg.authority).await {
        Ok(s) => s,
        Err(e) => {
            closed();
            return Err(e.into());
        }
    };
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = match sender.send_request(up_req).await {
        Ok(r) => r,
        Err(e) => {
            closed();
            return Err(e.into()); // hyper drops the downstream connection, no response written
        }
    };

    let (rparts, rbody) = resp.into_parts();
    let mut out = Response::new(tee(rbody, capture_file(&cfg, n, "resp")));
    *out.status_mut() = rparts.status;
    *out.headers_mut() = filtered(&rparts.headers);
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<(), Err> {
    let (mut upstream, mut capture) = (None, None);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--upstream" => upstream = args.next(),
            "--capture-dir" => capture = args.next().map(PathBuf::from),
            _ => return Err(format!("unknown argument {a}").into()),
        }
    }
    let upstream = upstream.ok_or("--upstream http://HOST:PORT is required")?;
    let authority = upstream
        .strip_prefix("http://")
        .ok_or("only http:// upstreams are supported")?
        .trim_end_matches('/')
        .to_string();
    if let Some(dir) = &capture {
        std::fs::create_dir_all(dir)?;
    }
    let cfg = Arc::new(Cfg { authority, capture, counter: AtomicUsize::new(0) });

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    println!("{{\"listen\":\"{}\"}}", listener.local_addr()?);
    std::io::stdout().flush()?;
    eprintln!("{{\"event\":\"host_header_rewritten_to_upstream_authority\"}}");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            accepted = listener.accept() => {
                let (sock, _) = accepted?;
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| relay(req, cfg.clone()));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(sock), svc)
                        .await;
                });
            }
        }
    }
}
