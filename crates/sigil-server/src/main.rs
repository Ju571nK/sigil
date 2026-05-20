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
    }
    Ok(())
}

fn build_state(cfg: &ServerConfig) -> Result<SharedState> {
    use sigil_server::auth::ReadToken;
    use sigil_server::boot_rebuild::rebuild_from_jsonl;
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

    let fleet_index = FleetIndex::new();
    tracing::info!("boot rebuild: scanning JSONL");
    let t0 = std::time::Instant::now();
    let built = rebuild_from_jsonl(&cfg.events_out_dir).context("boot rebuild")?;
    let n = built.len();
    fleet_index.replace(built);
    tracing::info!(hosts = n, elapsed_ms = ?t0.elapsed().as_millis(), "boot rebuild complete");

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

    Ok(Arc::new(AppState {
        events_out_dir: cfg.events_out_dir.clone(),
        policy_bundle_path: cfg.policy_bundle_path.clone(),
        high_water_path: cfg.high_water_path(),
        allowlist,
        high_water: Mutex::new(high_water),
        fleet_index,
        read_token,
        license_state,
        active_window_days,
    }))
}

async fn run(cfg: ServerConfig) -> Result<()> {
    let state = build_state(&cfg)?;
    let app = build_router(state);

    if cfg.mtls_enabled() {
        let tls = build_mtls(&cfg)?;
        tracing::info!(bind = %cfg.bind, "starting sigil-server (mTLS)");
        axum_server::bind_rustls(cfg.bind, tls)
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
