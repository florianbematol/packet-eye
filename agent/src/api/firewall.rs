//! Windows Firewall rule management handlers.

use axum::extract::Path;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::error::{blocking, ApiError};
use crate::firewall::{self, BlockTarget, FirewallError, FirewallRule, RuleDirection};

impl From<FirewallError> for ApiError {
    fn from(e: FirewallError) -> Self {
        let code = match &e {
            FirewallError::Invalid(_) => StatusCode::BAD_REQUEST,
            FirewallError::NotAdmin => StatusCode::FORBIDDEN,
            FirewallError::NotFound => StatusCode::NOT_FOUND,
            FirewallError::Unsupported => StatusCode::NOT_IMPLEMENTED,
            FirewallError::Script(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError::new(code, e.to_string())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateReq {
    pub target: BlockTarget,
    #[serde(default = "default_direction")]
    pub direction: RuleDirection,
    #[serde(default)]
    pub note: Option<String>,
}

fn default_direction() -> RuleDirection {
    RuleDirection::Out
}

#[derive(Debug, Serialize)]
pub struct CreateResp {
    pub created: Vec<String>,
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Deserialize)]
pub struct PatchReq {
    pub enabled: bool,
}

pub async fn list() -> Result<Json<Vec<FirewallRule>>, ApiError> {
    Ok(Json(blocking(|| Ok(firewall::list_rules()?)).await?))
}

pub async fn create(Json(req): Json<CreateReq>) -> Result<Json<CreateResp>, ApiError> {
    let resp = blocking(move || {
        let created = firewall::add_block(&req.target, req.direction, req.note.as_deref())?;
        tracing::info!("firewall: created rule(s) {created:?}");
        Ok(CreateResp { created, rules: firewall::list_rules()? })
    })
    .await?;
    Ok(Json(resp))
}

pub async fn patch(
    Path(id): Path<String>,
    Json(req): Json<PatchReq>,
) -> Result<Json<Vec<FirewallRule>>, ApiError> {
    let rules = blocking(move || {
        firewall::set_enabled(&id, req.enabled)?;
        Ok(firewall::list_rules()?)
    })
    .await?;
    Ok(Json(rules))
}

pub async fn delete(Path(id): Path<String>) -> Result<Json<Vec<FirewallRule>>, ApiError> {
    let rules = blocking(move || {
        firewall::delete_rule(&id)?;
        tracing::info!("firewall: deleted rule {id}");
        Ok(firewall::list_rules()?)
    })
    .await?;
    Ok(Json(rules))
}
