//! HTTP + WebSocket API surface served by the agent.

mod alerts;
mod capture;
mod geoip;
pub mod self_ip;
mod ws;

use std::sync::Arc;

use axum::routing::{get, post};
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
        .route("/api/geoip/info", get(geoip::info))
        .route("/api/geoip/update", post(geoip::update))
        .route("/ws", get(ws::ws_handler))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}
