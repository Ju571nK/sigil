use anyhow::{Context, Result};
use clap::Parser;
use sigil_server::allowlist;
use sigil_server::app::{build_router, AppState, SharedState};
use sigil_server::cli::{Cli, Command};
use sigil_server::config::ServerConfig;
use sigil_server::persist::HighWater;
use std::sync::{Arc, Mutex};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    // rustls 0.23 needs an explicit crypto provider; we built with the `ring` feature.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config } => {
            let cfg = ServerConfig::load(&config)
                .with_context(|| format!("load config {}", config.display()))?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(run(cfg))?;
        }
        Command::EnrollToken {
            config,
            host_id,
            ttl,
        } => {
            let cfg = ServerConfig::load(&config)
                .with_context(|| format!("load config {}", config.display()))?;
            enroll_token(&cfg, &host_id, &ttl)?;
        }
    }
    Ok(())
}

/// #184 — `sigil-server enroll-token`: issue one single-use, per-host token.
/// Prints the plaintext to stdout ONCE; only the hash is persisted.
fn enroll_token(cfg: &ServerConfig, host_id: &str, ttl: &str) -> Result<()> {
    use sigil_server::enroll::tokens::TokenStore;

    let tokens_path = cfg
        .enroll_tokens_path
        .as_ref()
        .context("enroll_tokens_path not set in config — enrollment is not configured")?;
    // Validate host_id is a UUID up front (matches the server's check).
    anyhow::ensure!(
        uuid::Uuid::parse_str(host_id).is_ok(),
        "host_id must be a valid UUID"
    );
    let ttl = parse_ttl(ttl).with_context(|| format!("invalid --ttl {ttl:?}"))?;
    let now = time::OffsetDateTime::now_utc();
    let expires_at = now + ttl;
    let plaintext = TokenStore::issue(tokens_path, host_id, expires_at, now)
        .map_err(|e| anyhow::anyhow!("issue token: {e}"))?;
    // The plaintext is shown exactly once; the store holds only its hash.
    println!("{plaintext}");
    eprintln!(
        "enrollment token issued for host_id={host_id}, expires_at={} (store: {})",
        expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        tokens_path.display()
    );
    eprintln!("note: this token is shown only once; only its blake3 hash is stored.");
    Ok(())
}

/// Parse a simple TTL like `1h`, `30m`, `45s`, `2d`. No unit ⇒ error.
fn parse_ttl(s: &str) -> Result<time::Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .context("ttl must be <number><unit>, e.g. 1h")?,
    );
    let n: i64 = num.parse().context("ttl number")?;
    anyhow::ensure!(n > 0, "ttl must be positive");
    let d = match unit {
        "s" => time::Duration::seconds(n),
        "m" => time::Duration::minutes(n),
        "h" => time::Duration::hours(n),
        "d" => time::Duration::days(n),
        other => anyhow::bail!("unknown ttl unit {other:?}; use s/m/h/d"),
    };
    Ok(d)
}

fn build_state(cfg: &ServerConfig) -> Result<SharedState> {
    use sigil_server::auth::ReadToken;
    use sigil_server::fleet_index::FleetIndex;

    let allowlist =
        allowlist::load(cfg.host_allowlist_path.as_deref()).context("load host allowlist")?;
    let high_water = HighWater::load(&cfg.high_water_path()).context("load high-water map")?;

    let read_token = ReadToken::from_env();
    if read_token.is_enabled() {
        tracing::info!("read API enabled (SIGIL_SERVER_READ_TOKEN set)");
    } else {
        tracing::warn!("SIGIL_SERVER_READ_TOKEN unset — read API disabled (404)");
    }

    // Fleet index starts empty; populated asynchronously in run() so the
    // listener can open immediately and boot_gate can serve 503 until ready (#19).
    let fleet_index = FleetIndex::new();

    let now = time::OffsetDateTime::now_utc();
    let active_window_days = cfg
        .license
        .as_ref()
        .and_then(|l| l.active_window_days)
        .unwrap_or(sigil_server::license_state::DEFAULT_ACTIVE_WINDOW_DAYS);
    let license_state = sigil_server::license_state::load_and_log(
        cfg.license.as_ref().and_then(|l| l.path.as_deref()),
        now,
    );

    let audit_dir = cfg.high_water_path();
    let audit_dir = audit_dir
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let audit_key = sigil_server::audit_key::AuditKey::load_or_create(audit_dir);
    match &audit_key {
        Some(k) => tracing::info!(pubkey_id = %k.pubkey_id, "audit signing key ready"),
        None => tracing::warn!("audit signing key unavailable; license audit log disabled"),
    }

    // #184 — enrollment state. Off unless cert+key+tokens AND host_allowlist are
    // all configured AND boot validation passes (see EnrollState::load).
    let enroll_audit_path = audit_dir.join("enrollment-audit.jsonl");
    let enroll = sigil_server::enroll::EnrollState::load(
        cfg.enroll_ca_cert_path.as_deref(),
        cfg.enroll_ca_key_path.as_deref(),
        cfg.enroll_tokens_path.as_deref(),
        cfg.host_allowlist_path.as_deref(),
        cfg.mtls_enabled(),
        cfg.enroll_cert_days,
        enroll_audit_path,
        cfg.enroll_issuer_fingerprints.clone(),
    );
    if enroll.is_some() {
        tracing::info!("enrollment endpoint enabled (POST /v1/enroll)");
    }

    Ok(Arc::new(AppState {
        events_out_dir: cfg.events_out_dir.clone(),
        policy_bundle_path: cfg.policy_bundle_path.clone(),
        rule_packs_bundle_path: cfg.rule_packs_bundle_path.clone(),
        artifacts_dir: cfg.artifacts_dir.clone(),
        high_water_path: cfg.high_water_path(),
        allowlist: parking_lot::RwLock::new(allowlist),
        high_water: Mutex::new(high_water),
        fleet_index,
        read_token,
        license_state,
        active_window_days,
        audit_key,
        audit_head: Mutex::new(None),
        allowlist_path: cfg.host_allowlist_path.clone(),
        enroll,
        // #194.2 — ServerConfig::load refused to start if this is set
        // without mTLS, so `true` here implies the mTLS listener (and thus
        // PeerIdentity injection) is active.
        events_require_cert_host_match: cfg.events_require_cert_host_match,
    }))
}

async fn run(cfg: ServerConfig) -> Result<()> {
    let state = build_state(&cfg)?;

    // Boot rebuild runs off-thread so the listener opens immediately; boot_gate
    // serves 503 + Retry-After until this flips boot_complete to true (#19).
    let boot_complete = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        use sigil_server::boot_rebuild::rebuild_from_jsonl;
        use std::sync::atomic::Ordering;
        let fleet_index = state.fleet_index.clone();
        let events_out_dir = cfg.events_out_dir.clone();
        let boot_complete = boot_complete.clone();
        tokio::spawn(async move {
            tracing::info!("boot rebuild: scanning JSONL (async)");
            let t0 = std::time::Instant::now();
            match tokio::task::spawn_blocking(move || rebuild_from_jsonl(&events_out_dir)).await {
                Ok(Ok(built)) => {
                    let n = built.len();
                    fleet_index.replace(built);
                    tracing::info!(hosts = n, elapsed_ms = ?t0.elapsed().as_millis(), "boot rebuild complete");
                }
                Ok(Err(e)) => {
                    tracing::error!(error = ?e, "boot rebuild failed; serving empty index")
                }
                Err(e) => {
                    tracing::error!(error = ?e, "boot rebuild task panicked; serving empty index")
                }
            }
            // Unconditionally flip ready on every completion path (success/error/panic-join)
            // so a failed rebuild serves an empty index rather than 503-ing forever. (The
            // only way this is skipped is if the spawned task itself panics before here —
            // not reachable today: replace() is infallible and the join is matched above.)
            boot_complete.store(true, Ordering::Relaxed);
        });
    }

    // License audit task: append a durable, signed, hash-chained record on
    // boot, every 6h, and on any ok/over_limit transition. Append-only;
    // never blocks serving. No signing key ⇒ no lines (measure-don't-block).
    {
        let state = state.clone();
        let audit_path = state
            .high_water_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("license-audit.jsonl");
        let window_days = state.active_window_days;
        let version = env!("CARGO_PKG_VERSION");
        tokio::spawn(async move {
            use sigil_core::audit::{sign_record, AuditHead, GENESIS_PREV_HASH};
            use sigil_core::license::status::{compute_status, LicenseStatusState};
            use sigil_server::license_state::{
                append_audit_line, build_audit_record, resume_chain, should_audit,
            };

            let key = match state.audit_key.as_ref() {
                Some(k) => k,
                None => return,
            };
            let (mut seq, mut prev_hash) =
                resume_chain(&audit_path).unwrap_or((0, GENESIS_PREV_HASH.to_string()));
            let mut last: Option<LicenseStatusState> = None;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
            loop {
                tick.tick().await;
                let now = time::OffsetDateTime::now_utc();
                let active = state
                    .fleet_index
                    .active_host_count(now, time::Duration::days(window_days as i64));
                let status = compute_status(&state.license_state, active, window_days);
                if should_audit(last, status.state) {
                    let record = build_audit_record(&status, seq, prev_hash.clone(), now, version);
                    match sign_record(record, &key.signing_key, &key.pubkey_id) {
                        Ok(signed) => {
                            append_audit_line(
                                &audit_path,
                                &serde_json::to_string(&signed).unwrap(),
                            );
                            prev_hash = signed.hash.clone();
                            seq += 1;
                            *state.audit_head.lock().unwrap() = Some(AuditHead {
                                seq: signed.record.seq,
                                hash: signed.hash,
                                sig: signed.sig,
                                pubkey_id: signed.pubkey_id,
                            });
                            last = Some(status.state);
                        }
                        Err(e) => tracing::warn!(%e, "license audit sign failed"),
                    }
                }
            }
        });
    }

    let app = build_router(state).layer(axum::middleware::from_fn_with_state(
        boot_complete.clone(),
        sigil_server::app::boot_gate,
    ));

    if cfg.mtls_enabled() {
        let tls = build_mtls(&cfg)?;
        tracing::info!(bind = %cfg.bind, "starting sigil-server (mTLS)");
        // #194 — PeerCertAcceptor wraps axum-server's rustls acceptor (same
        // handshake + timeout) and exposes the verified client cert to
        // handlers as an `Extension<Arc<PeerIdentity>>` on every request.
        axum_server::bind(cfg.bind)
            .acceptor(sigil_server::tls_accept::PeerCertAcceptor::new(tls))
            .serve(app.into_make_service())
            .await
            .context("axum_server serve (mTLS)")?;
    } else {
        tracing::warn!(bind = %cfg.bind, "starting sigil-server (PLAIN HTTP — no mTLS)");
        let listener = tokio::net::TcpListener::bind(cfg.bind)
            .await
            .with_context(|| format!("bind {}", cfg.bind))?;
        axum::serve(listener, app).await.context("axum serve")?;
    }
    Ok(())
}

fn build_mtls(cfg: &ServerConfig) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
        let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let mut rd = std::io::BufReader::new(&data[..]);
        let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
            .collect::<Result<_, _>>()
            .with_context(|| format!("parse certs from {}", path.display()))?;
        anyhow::ensure!(!certs.is_empty(), "no certs in {}", path.display());
        Ok(certs)
    }
    fn load_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
        let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let mut rd = std::io::BufReader::new(&data[..]);
        rustls_pemfile::private_key(&mut rd)
            .with_context(|| format!("parse key from {}", path.display()))?
            .with_context(|| format!("no private key in {}", path.display()))
    }

    let server_certs = load_certs(cfg.tls_cert_path.as_ref().unwrap())?;
    let server_key = load_key(cfg.tls_key_path.as_ref().unwrap())?;
    let client_ca = load_certs(cfg.client_ca_path.as_ref().unwrap())?;

    let mut roots = rustls::RootCertStore::empty();
    for c in client_ca {
        roots.add(c).context("add client CA to root store")?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build client cert verifier")?;
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .context("build rustls ServerConfig")?;
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_ttl;
    use time::Duration;

    #[test]
    fn parse_ttl_units() {
        assert_eq!(parse_ttl("45s").unwrap(), Duration::seconds(45));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_ttl("1h").unwrap(), Duration::hours(1));
        assert_eq!(parse_ttl("2d").unwrap(), Duration::days(2));
    }

    #[test]
    fn parse_ttl_rejects_bad_input() {
        assert!(parse_ttl("1h30m").is_err()); // unknown unit "h30m"
        assert!(parse_ttl("h").is_err()); // no number
        assert!(parse_ttl("10").is_err()); // no unit
        assert!(parse_ttl("0h").is_err()); // non-positive
        assert!(parse_ttl("-1h").is_err()); // leading '-' is not a digit
    }
}
