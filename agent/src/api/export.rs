//! `.pcapng` export of the in-memory capture ring.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use super::error::{blocking, ApiError};
use crate::capture::pcap_ring::RingInfo;
use crate::capture::types::Protocol;
use crate::enrich::domains::FlowKey;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    /// `tcp` / `udp` / `icmp` — together with `a` and `b`, restricts the
    /// export to a single connection.
    pub proto: Option<String>,
    /// One endpoint, `ip:port` (`[v6]:port` for IPv6).
    pub a: Option<String>,
    /// The other endpoint.
    pub b: Option<String>,
}

pub async fn info(State(state): State<Arc<AppState>>) -> Json<RingInfo> {
    Json(state.pcap.info())
}

pub async fn pcapng(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let flow = match (&q.proto, &q.a, &q.b) {
        (None, None, None) => None,
        (Some(proto), Some(a), Some(b)) => {
            let proto = match proto.to_ascii_lowercase().as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                "icmp" => Protocol::Icmp,
                other => return Err(ApiError::bad_request(format!("unsupported proto: {other}"))),
            };
            let a: SocketAddr = a.parse().map_err(|_| ApiError::bad_request("bad endpoint `a`"))?;
            let b: SocketAddr = b.parse().map_err(|_| ApiError::bad_request("bad endpoint `b`"))?;
            Some(FlowKey::new(proto, (a.ip(), a.port()), (b.ip(), b.port())))
        }
        _ => return Err(ApiError::bad_request("give all of proto, a and b, or none")),
    };

    let ring = state.pcap.clone();
    let (bytes, packets) = blocking(move || Ok(ring.export(flow))).await?;
    if packets == 0 {
        return Err(ApiError::new(
            axum::http::StatusCode::NOT_FOUND,
            "no buffered packets match — start a capture first",
        ));
    }

    let stamp = time::OffsetDateTime::now_utc()
        .format(time::macros::format_description!("[year][month][day]-[hour][minute][second]"))
        .unwrap_or_else(|_| "capture".into());
    let name = if flow.is_some() {
        format!("packet-eye-{stamp}-connection.pcapng")
    } else {
        format!("packet-eye-{stamp}.pcapng")
    };
    let mut resp = bytes.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = HeaderValue::from_str(&packets.to_string()) {
        h.insert("x-packet-count", v);
    }
    Ok(resp)
}
