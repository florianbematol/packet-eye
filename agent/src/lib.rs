//! Packet Eye local agent.

pub mod alerts;
pub mod api;
pub mod capture;
pub mod enrich;
pub mod state;
pub mod threats;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{fmt, EnvFilter};

use crate::alerts::AlertEngine;
use crate::enrich::{
    dns::DnsResolver,
    geoip::{self, GeoIpResolver},
    local_ips::LocalIps,
    process::ProcessResolver,
    Enricher,
};
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

    /// Allow any origin to call the API (handy for `vite dev`).
    #[arg(long, default_value_t = true)]
    pub permissive_cors: bool,

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

    // Build enrichment pipeline.
    let geoip: Arc<GeoIpResolver> = geoip::open_with_args(&args);
    let local: Arc<LocalIps> = LocalIps::new();
    let processes: Arc<ProcessResolver> = ProcessResolver::new();
    let dns: Arc<DnsResolver> = DnsResolver::new();

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

    let enricher = Arc::new(Enricher::new(geoip.clone(), processes, dns, local));

    let threats = load_threats();
    let alerts = AlertEngine::new(threats);

    let state = Arc::new(AppState::new(enricher, geoip, alerts));

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

    // Tracing + CORS layers.
    let cors = if args.permissive_cors {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        CorsLayer::new()
    };
    app = app.layer(TraceLayer::new_for_http()).layer(cors);

    let listener = TcpListener::bind(args.listen).await?;
    tracing::info!("listening on http://{}", args.listen);
    if ui_dir.is_some() {
        tracing::info!("open http://{} in your browser", args.listen);
    }
    axum::serve(listener, app).await?;
    Ok(())
}
