//! HTTP handlers for alert rules and threat-list state.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::alerts::AlertRules;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct ThreatStats {
    pub total_ranges: usize,
}

pub async fn get_rules(State(state): State<Arc<AppState>>) -> Json<AlertRules> {
    Json(state.alerts.rules())
}

pub async fn put_rules(
    State(state): State<Arc<AppState>>,
    Json(rules): Json<AlertRules>,
) -> Json<AlertRules> {
    state.alerts.set_rules(rules);
    Json(state.alerts.rules())
}

pub async fn threats(State(state): State<Arc<AppState>>) -> Json<ThreatStats> {
    Json(ThreatStats {
        total_ranges: state.alerts.threat_count(),
    })
}
