//! Shared JSON error type for HTTP handlers.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

#[derive(Debug)]
pub struct ApiError {
    code: StatusCode,
    msg: String,
}

impl ApiError {
    pub fn new(code: StatusCode, msg: impl Into<String>) -> Self {
        Self { code, msg: msg.into() }
    }
    pub fn msg(e: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
    pub fn bad_request(e: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::BAD_REQUEST, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "error": self.msg });
        (self.code, Json(body)).into_response()
    }
}

/// Run blocking work (SQLite, PowerShell…) off the async runtime.
pub async fn blocking<T, F>(f: F) -> Result<T, ApiError>
where
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::msg(format!("task failed: {e}")))?
}
