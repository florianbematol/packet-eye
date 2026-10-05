//! HTTP + WebSocket API surface served by the agent.

mod alerts;
mod capture;
pub mod error;
mod export;
mod firewall;
mod geoip;
mod history;
pub mod self_ip;
mod ws;

use std::sync::Arc;

use axum::routing::{get, patch, post};
use axum::Router;

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/self", get(self_ip::handler))
        .route("/api/devices", get(capture::list_devices))
        .route("/api/capture/start", post(capture::start_capture))
        .route("/api/capture/stop", post(capture::stop_capture))
        .route("/api/capture/status", get(capture::status))
        .route("/api/stats", get(capture::stats))
        .route("/api/alerts/rules", get(alerts::get_rules).put(alerts::put_rules))
        .route("/api/threats", get(alerts::threats))
        .route("/api/threats/update", post(alerts::update_threats))
        .route("/api/geoip/info", get(geoip::info))
        .route("/api/geoip/update", post(geoip::update))
        .route("/api/export/info", get(export::info))
        .route("/api/export/pcapng", get(export::pcapng))
        .route("/api/history/info", get(history::info))
        .route("/api/history/timeline", get(history::timeline))
        .route("/api/history/flows", get(history::flows))
        .route("/api/history/apps", get(history::apps))
        .route("/api/history/alerts", get(history::alerts))
        .route(
            "/api/history/settings",
            get(history::get_settings).put(history::put_settings),
        )
        .route("/api/history/clear", post(history::clear))
        .route("/api/firewall/rules", get(firewall::list).post(firewall::create))
        .route(
            "/api/firewall/rules/:id",
            patch(firewall::patch).delete(firewall::delete),
        )
        .route("/ws", get(ws::ws_handler))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
