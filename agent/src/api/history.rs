//! History (SQLite) query handlers.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;

use super::error::{blocking, ApiError};
use crate::history::{
    AlertRow, AppRow, FlowRow, HistoryInfo, HistorySettings, RangeQuery, TimelinePoint,
};
use crate::state::AppState;

pub async fn info(State(state): State<Arc<AppState>>) -> Result<Json<HistoryInfo>, ApiError> {
    let h = state.history.clone();
    Ok(Json(blocking(move || h.info().map_err(ApiError::msg)).await?))
}

pub async fn timeline(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<TimelinePoint>>, ApiError> {
    let h = state.history.clone();
    Ok(Json(blocking(move || h.timeline(&q).map_err(ApiError::msg)).await?))
}

pub async fn flows(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<FlowRow>>, ApiError> {
    let h = state.history.clone();
    Ok(Json(blocking(move || h.flows(&q).map_err(ApiError::msg)).await?))
}

pub async fn apps(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<AppRow>>, ApiError> {
    let h = state.history.clone();
    Ok(Json(blocking(move || h.apps(&q).map_err(ApiError::msg)).await?))
}

pub async fn alerts(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<AlertRow>>, ApiError> {
    let h = state.history.clone();
    Ok(Json(blocking(move || h.alerts(&q).map_err(ApiError::msg)).await?))
}

pub async fn get_settings(State(state): State<Arc<AppState>>) -> Json<HistorySettings> {
    Json(state.history.settings())
}

pub async fn put_settings(
    State(state): State<Arc<AppState>>,
    Json(s): Json<HistorySettings>,
) -> Result<Json<HistorySettings>, ApiError> {
    let h = state.history.clone();
    let saved = blocking(move || {
        let saved = h.set_settings(s).map_err(ApiError::msg)?;
        h.purge().map_err(ApiError::msg)?;
        Ok(saved)
    })
    .await?;
    Ok(Json(saved))
}

pub async fn clear(State(state): State<Arc<AppState>>) -> Result<Json<HistoryInfo>, ApiError> {
    let h = state.history.clone();
    Ok(Json(
        blocking(move || {
            h.clear().map_err(ApiError::msg)?;
            h.info().map_err(ApiError::msg)
        })
        .await?,
    ))
}
