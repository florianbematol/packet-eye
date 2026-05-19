//! Runtime GeoIP database management: introspection + on-demand update
//! from the P3TERX/GeoLite.mmdb mirror.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::state::AppState;

const P3TERX_BASE: &str = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download";
const FILES: &[(&str, u64)] = &[
    // (filename, min size in bytes for sanity check)
    ("GeoLite2-City.mmdb", 50 * 1024 * 1024),
    ("GeoLite2-ASN.mmdb", 5 * 1024 * 1024),
];

#[derive(Debug, Clone, Serialize)]
pub struct DbFileInfo {
    pub filename: String,
    pub path: Option<String>,
    pub exists: bool,
    pub size_bytes: u64,
    pub modified_iso: Option<String>,
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoIpInfo {
    pub city: DbFileInfo,
    pub asn: DbFileInfo,
    pub override_dir: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateResp {
    pub ok: bool,
    pub elapsed_ms: u128,
    pub city: DbFileInfo,
    pub asn: DbFileInfo,
}

/// Concurrent-update guard. Updates are slow (multi-MB downloads) so we
/// don't want two clients running it at once. We use a plain atomic
/// because handlers are async and we mustn't hold a guard across an await.
static UPDATE_RUNNING: AtomicBool = AtomicBool::new(false);

pub async fn info(State(_state): State<Arc<AppState>>) -> Json<GeoIpInfo> {
    let dir = override_dir();
    Json(GeoIpInfo {
        city: file_info(FILES[0].0),
        asn: file_info(FILES[1].0),
        override_dir: dir.to_string_lossy().into_owned(),
    })
}

pub async fn update(
    State(state): State<Arc<AppState>>,
) -> Result<Json<UpdateResp>, ApiError> {
    if UPDATE_RUNNING.swap(true, Ordering::AcqRel) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "update already in progress",
        ));
    }
    // Always release the flag, even on early returns / panics.
    let _release = ReleaseOnDrop;

    let started = Instant::now();
    let dir = override_dir();
    std::fs::create_dir_all(&dir).map_err(ApiError::msg)?;

    let client = reqwest::Client::builder()
        .user_agent("packet-eye-agent/0.1")
        .build()
        .map_err(ApiError::msg)?;

    for (name, min_size) in FILES {
        let url = format!("{P3TERX_BASE}/{name}");
        let dest = dir.join(name);
        let tmp = dir.join(format!("{name}.download"));
        if tmp.exists() {
            let _ = std::fs::remove_file(&tmp);
        }

        tracing::info!("downloading {url} -> {}", dest.display());
        let resp = client.get(&url).send().await.map_err(ApiError::msg)?;
        if !resp.status().is_success() {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("{url} returned {}", resp.status()),
            ));
        }
        let bytes = resp.bytes().await.map_err(ApiError::msg)?;
        if (bytes.len() as u64) < *min_size {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!(
                    "{name} download too small: {} bytes (min {})",
                    bytes.len(),
                    min_size
                ),
            ));
        }
        std::fs::write(&tmp, &bytes).map_err(ApiError::msg)?;
        if dest.exists() {
            std::fs::remove_file(&dest).map_err(ApiError::msg)?;
        }
        std::fs::rename(&tmp, &dest).map_err(ApiError::msg)?;
    }

    let city_path = dir.join(FILES[0].0);
    let asn_path = dir.join(FILES[1].0);
    state
        .geoip
        .reload(&city_path, &asn_path)
        .map_err(ApiError::msg)?;

    Ok(Json(UpdateResp {
        ok: true,
        elapsed_ms: started.elapsed().as_millis(),
        city: file_info(FILES[0].0),
        asn: file_info(FILES[1].0),
    }))
}

struct ReleaseOnDrop;
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        UPDATE_RUNNING.store(false, Ordering::Release);
    }
}

fn override_dir() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("dev", "packet-eye", "packet-eye") {
        return dirs.data_dir().join("geoip");
    }
    PathBuf::from("./geoip")
}

fn file_info(name: &str) -> DbFileInfo {
    // Resolve to whichever path is currently active (override > cwd > exe).
    let (resolved, source) = resolve_active_path(name);
    if let Some(p) = resolved {
        let meta = std::fs::metadata(&p).ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified_iso = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| {
                let dt: time::OffsetDateTime = t.into();
                dt.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            });
        DbFileInfo {
            filename: name.to_string(),
            path: Some(p.to_string_lossy().into_owned()),
            exists: size > 0,
            size_bytes: size,
            modified_iso,
            source,
        }
    } else {
        DbFileInfo {
            filename: name.to_string(),
            path: None,
            exists: false,
            size_bytes: 0,
            modified_iso: None,
            source: "missing",
        }
    }
}

fn resolve_active_path(name: &str) -> (Option<PathBuf>, &'static str) {
    // 1. Override (%APPDATA%/.../geoip)
    let p = override_dir().join(name);
    if p.is_file() {
        return (Some(p), "override");
    }
    // 2. <cwd>/resources/  and  <cwd>/agent/resources/
    if let Ok(cwd) = std::env::current_dir() {
        for cand in [
            cwd.join("resources").join(name),
            cwd.join("agent").join("resources").join(name),
        ] {
            if cand.is_file() {
                return (Some(cand), "cwd");
            }
        }
    }
    // 3. <exe-dir>/resources  and  <exe-dir>/../../resources
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let p = parent.join("resources").join(name);
            if p.is_file() {
                return (Some(p), "exe");
            }
            if let Some(grand) = parent.parent().and_then(|p| p.parent()) {
                let p = grand.join("resources").join(name);
                if p.is_file() {
                    return (Some(p), "exe");
                }
            }
        }
    }
    (None, "missing")
}

// Local copy of ApiError so we don't have to make capture::ApiError public.
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
        Self {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            msg: e.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({"error": self.msg});
        (self.code, Json(body)).into_response()
    }
}
