//! Resolve "this machine's" public IP and run it through GeoIP so the
//! frontend can pin the user on the 3D globe.
//!
//! We try a couple of well-known echo services in order. Result is cached
//! in memory for a few minutes; the request is best-effort, errors are
//! reported as `{ip: null, geo: null}`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::Json;
use parking_lot::Mutex;
use serde::Serialize;

use crate::enrich::geoip::GeoLookup;
use crate::state::AppState;

const CACHE_TTL: Duration = Duration::from_secs(300);
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const ECHO_URLS: &[&str] = &[
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipv4.icanhazip.com",
];

#[derive(Debug, Clone, Serialize)]
pub struct SelfResp {
    pub ip: Option<String>,
    pub geo: Option<GeoLookup>,
}

#[derive(Default)]
pub struct SelfCache {
    last: Mutex<Option<(Instant, SelfResp)>>,
}

impl SelfCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

pub async fn handler(State(state): State<Arc<AppState>>) -> Json<SelfResp> {
    {
        let cache = state.self_cache.last.lock();
        if let Some((at, resp)) = cache.as_ref() {
            if at.elapsed() < CACHE_TTL {
                return Json(resp.clone());
            }
        }
    }

    let resp = match resolve_ip().await {
        Some(ip) => {
            let parsed = ip.parse().ok();
            let geo = parsed.and_then(|p| state.geoip.lookup(&p));
            SelfResp { ip: Some(ip), geo }
        }
        None => SelfResp { ip: None, geo: None },
    };

    *state.self_cache.last.lock() = Some((Instant::now(), resp.clone()));
    Json(resp)
}

async fn resolve_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("packet-eye-agent/0.1")
        .build()
        .ok()?;

    for url in ECHO_URLS {
        match client.get(*url).send().await {
            Ok(r) if r.status().is_success() => match r.text().await {
                Ok(text) => {
                    let ip = text.trim().to_string();
                    if !ip.is_empty() && ip.len() < 64 {
                        tracing::debug!("self IP via {url}: {ip}");
                        return Some(ip);
                    }
                }
                Err(e) => tracing::debug!("body read from {url} failed: {e}"),
            },
            Ok(r) => tracing::debug!("{url} returned {}", r.status()),
            Err(e) => tracing::debug!("{url} request failed: {e}"),
        }
    }
    None
}
