//! HTTP handlers for alert rules and threat-list state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use super::error::{blocking, ApiError};
use crate::alerts::AlertRules;
use crate::state::AppState;
use crate::threats::{self, ThreatsInfo, UpdateResult};

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

pub async fn threats(State(state): State<Arc<AppState>>) -> Result<Json<ThreatsInfo>, ApiError> {
    let matcher = state.threats.clone();
    Ok(Json(blocking(move || Ok(threats::info(&matcher))).await?))
}

static UPDATING: AtomicBool = AtomicBool::new(false);

struct Release;
impl Drop for Release {
    fn drop(&mut self) {
        UPDATING.store(false, Ordering::Release);
    }
}

#[derive(Debug, Serialize)]
pub struct UpdateResp {
    pub results: Vec<UpdateResult>,
    pub info: ThreatsInfo,
}

/// Re-download the upstream lists, then hot-reload the matcher.
pub async fn update_threats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<UpdateResp>, ApiError> {
    if UPDATING.swap(true, Ordering::AcqRel) {
        return Err(ApiError::new(StatusCode::CONFLICT, "update already in progress"));
    }
    let _release = Release;
    let results = threats::download_all().await;
    let matcher = state.threats.clone();
    let info = blocking(move || {
        let n = threats::reload(&matcher);
        tracing::info!("threat lists reloaded: {n} ranges");
        Ok(threats::info(&matcher))
    })
    .await?;
    Ok(Json(UpdateResp { results, info }))
}
