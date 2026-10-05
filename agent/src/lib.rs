//! Packet Eye local agent.

pub mod alerts;
pub mod api;
pub mod capture;
pub mod enrich;
pub mod firewall;
pub mod history;
pub mod security;
pub mod state;
pub mod threats;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::http::{header, Method};
use clap::Parser;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{fmt, EnvFilter};

use crate::alerts::AlertEngine;
use crate::capture::pcap_ring::PcapRing;
use crate::enrich::{
    domains::DomainSniffer,
    geoip::{self, GeoIpResolver},
    local_ips::LocalIps,
    process::ProcessResolver,
    Enricher,
};
use crate::history::History;
use crate::security::SecurityConfig;
use crate::state::AppState;
use crate::threats::load_default as load_threats;

/// Command-line options.
#[derive(Debug, Parser)]
#[command(name = "packet-eye-agent", version)]
pub struct Args {
    /// Listen address. Use `127.0.0.1` (default) to keep the agent on
    /// loopback only.
    #[arg(long, default_value = "127.0.0.1:8088")]
    pub listen: SocketAddr,

    /// Path to GeoLite2-City.mmdb. Defaults to ./resources/GeoLite2-City.mmdb
    /// then %APPDATA%/packet-eye/geoip/GeoLite2-City.mmdb.
    #[arg(long)]
    pub city_db: Option<std::path::PathBuf>,

    /// Path to GeoLite2-ASN.mmdb (same lookup order).
    #[arg(long)]
    pub asn_db: Option<std::path::PathBuf>,

    /// Extra web origin allowed to call the API, e.g.
    /// `http://192.168.1.20:3000`. Loopback origins (localhost,
    /// 127.0.0.1, [::1], any port) are always allowed. Repeatable.
    #[arg(long = "allow-origin", value_name = "ORIGIN")]
    pub allow_origins: Vec<String>,

    /// Extra hostname accepted in the `Host` header (DNS-rebinding
    /// protection). Loopback names and the listen IP are always allowed.
    /// Repeatable.
    #[arg(long = "allow-host", value_name = "HOST")]
    pub allow_hosts: Vec<String>,

    /// Memory budget for the raw-frame ring used by the `.pcapng` export,
    /// in MiB. `0` disables the export buffer.
    #[arg(long, default_value_t = 64)]
    pub pcap_buffer_mb: usize,

    /// Directory containing the built web UI (`npm run build` output).
    /// When found, the agent serves it at `/` so a single executable is
    /// enough. Defaults to auto-detecting `dist/` next to the repo.
    #[arg(long)]
    pub ui: Option<std::path::PathBuf>,

    /// Disable serving the web UI even if a `dist/` folder is found.
    #[arg(long, default_value_t = false)]
    pub no_ui: bool,
}

/// Find the built frontend. Order: `--ui`, `<cwd>/dist`, `<cwd>/../dist`,
/// `<exe-dir>/dist`, `<exe-dir>/../../../dist` (agent/target/release).
fn resolve_ui_dir(args: &Args) -> Option<std::path::PathBuf> {
    let has_index = |p: &std::path::Path| p.join("index.html").is_file();
    if let Some(p) = &args.ui {
        return has_index(p).then(|| p.clone());
    }
    let mut candidates = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("dist"));
        candidates.push(cwd.join("..").join("dist"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("dist"));
            candidates.push(dir.join("..").join("..").join("..").join("dist"));
        }
    }
    candidates.into_iter().find(|p| has_index(p))
}

pub async fn run(args: Args) -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tower_http=warn")),
        )
        .with_target(true)
        .try_init()
        .ok();

    tracing::info!("packet-eye-agent starting on {}", args.listen);
    if !args.listen.ip().is_loopback() {
        tracing::warn!(
            "listening on {} — the API has no authentication and is reachable from the network",
            args.listen
        );
    }

    // Build enrichment pipeline.
    let geoip: Arc<GeoIpResolver> = geoip::open_with_args(&args);
    let local: Arc<LocalIps> = LocalIps::new();
    let processes: Arc<ProcessResolver> = ProcessResolver::new();
    let domains: Arc<DomainSniffer> = DomainSniffer::new();

    processes
        .clone()
        .spawn_refresher(Duration::from_secs(2));

    {
        let local2 = local.clone();
        std::thread::Builder::new()
            .name("packet-eye-localips".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(30));
                local2.refresh();
            })
            .ok();
    }

    let enricher = Arc::new(Enricher::new(geoip.clone(), processes, domains, local));

    let threats = load_threats();
    let alerts = AlertEngine::new(threats.clone());
    let pcap = PcapRing::new(args.pcap_buffer_mb.saturating_mul(1024 * 1024));
    let history = History::open_default()?;

    let state = Arc::new(AppState::new(
        enricher,
        geoip,
        alerts,
        threats,
        pcap,
        history.clone(),
    ));

    spawn_history_tasks(history);

    // Build router.
    let mut app = api::router(state.clone());

    // Serve the built web UI (SPA) for every non-API path.
    let ui_dir = if args.no_ui { None } else { resolve_ui_dir(&args) };
    match &ui_dir {
        Some(dir) => {
            let dir = dir.canonicalize().unwrap_or_else(|_| dir.clone());
            tracing::info!("serving web UI from {}", dir.display());
            let index = dir.join("index.html");
            app = app.fallback_service(
                ServeDir::new(&dir).not_found_service(ServeFile::new(index)),
            );
        }
        None => tracing::warn!(
            "web UI not found (run `npm run build`, or pass --ui <dir>); serving API only"
        ),
    }

    // Security: Host + Origin allowlists, and a matching CORS policy.
    let sec = Arc::new(SecurityConfig::new(args.listen, &args.allow_origins, &args.allow_hosts));
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate({
            let pred = security::cors_predicate(sec.clone());
            move |origin, _req| pred(origin)
        }))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE])
        .expose_headers([
            header::CONTENT_DISPOSITION,
            header::HeaderName::from_static("x-packet-count"),
        ]);
    app = app
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(axum::middleware::from_fn_with_state(sec, security::guard));

    let listener = TcpListener::bind(args.listen).await?;
    tracing::info!("listening on http://{}", args.listen);
    if ui_dir.is_some() {
        tracing::info!("open http://{} in your browser", args.listen);
    }
    axum::serve(listener, app).await?;
    Ok(())
}

/// Flush the history aggregate every 10 s and purge old rows hourly.
fn spawn_history_tasks(history: Arc<History>) {
    let h = history.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let h = h.clone();
            match tokio::task::spawn_blocking(move || h.flush()).await {
                Ok(Err(e)) => tracing::warn!("history flush failed: {e:#}"),
                Err(e) => tracing::warn!("history flush task failed: {e}"),
                _ => {}
            }
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            let h = history.clone();
            if let Ok(Ok(n)) = tokio::task::spawn_blocking(move || h.purge()).await {
                if n > 0 {
                    tracing::info!("history: purged {n} expired rows");
                }
            }
        }
    });
}
