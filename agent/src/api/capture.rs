//! Capture-related HTTP handlers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use crate::capture::bpf::CaptureFilter;
use crate::capture::device::{self, DeviceInfo};
use crate::capture::runner::{CaptureHooks, Runner};
use crate::enrich::EnrichedPacket;
use crate::state::{AppState, StatsTick};

#[derive(Debug, Deserialize)]
pub struct StartReq {
    pub device: String,
    #[serde(default)]
    pub filter: CaptureFilter,
}

#[derive(Debug, Serialize)]
pub struct StatusResp {
    pub running: bool,
}

#[derive(Debug, Serialize)]
pub struct StatsResp {
    pub stats: StatsTick,
    pub running: bool,
}

pub async fn list_devices() -> Result<Json<Vec<DeviceInfo>>, ApiError> {
    let devs = device::list().map_err(ApiError::msg)?;
    Ok(Json(devs))
}

pub async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResp> {
    Json(StatusResp {
        running: state.is_running(),
    })
}

pub async fn stats(State(state): State<Arc<AppState>>) -> Json<StatsResp> {
    Json(StatsResp {
        stats: state.current_stats(),
        running: state.is_running(),
    })
}

pub async fn start_capture(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartReq>,
) -> Result<Json<StatusResp>, ApiError> {
    if state.is_running() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "capture already running",
        ));
    }

    // Build the per-packet callback: enrich + buffer + flush.
    let buffer: Arc<Mutex<BatchBuf>> = Arc::new(Mutex::new(BatchBuf::new()));
    let state2 = state.clone();
    let buffer2 = buffer.clone();
    let on_packet = std::sync::Arc::new(move |evt| {
        let enriched = state2.enricher.enrich(evt);
        let now = Instant::now();
        let to_flush = {
            let mut b = buffer2.lock();
            b.push(enriched, now)
        };
        if let Some(batch) = to_flush {
            state2.publish(batch);
        }
    });

    let hooks = CaptureHooks {
        sniffer: state.enricher.domains.clone(),
        ring: state.pcap.clone(),
    };
    let runner = Runner::spawn(&req.device, &req.filter, hooks, on_packet)
        .map_err(ApiError::msg)?;

    *state.runner.lock() = Some(runner);

    // Background flusher to drain leftover packets when traffic is sparse.
    {
        let state3 = state.clone();
        let buffer3 = buffer.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(500));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if !state3.is_running() {
                    // Final flush, then exit.
                    let leftover = buffer3.lock().drain();
                    if !leftover.is_empty() {
                        state3.publish(leftover);
                    }
                    break;
                }
                let now = Instant::now();
                let due = {
                    let mut b = buffer3.lock();
                    b.flush_if_due(now)
                };
                if let Some(batch) = due {
                    state3.publish(batch);
                }
            }
        });
    }

    Ok(Json(StatusResp { running: true }))
}

pub async fn stop_capture(
    State(state): State<Arc<AppState>>,
) -> Json<StatusResp> {
    if let Some(mut r) = state.runner.lock().take() {
        r.stop();
    }
    Json(StatusResp { running: false })
}

// ---- Tiny ring-style buffer used by start_capture ----

struct BatchBuf {
    buf: Vec<EnrichedPacket>,
    last_flush: Instant,
}

impl BatchBuf {
    const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
    const MAX_BATCH: usize = 4096;

    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            last_flush: Instant::now(),
        }
    }

    fn push(&mut self, p: EnrichedPacket, now: Instant) -> Option<Vec<EnrichedPacket>> {
        self.buf.push(p);
        if self.buf.len() >= Self::MAX_BATCH
            || now.duration_since(self.last_flush) >= Self::FLUSH_INTERVAL
        {
            self.last_flush = now;
            Some(std::mem::take(&mut self.buf))
        } else {
            None
        }
    }

    fn flush_if_due(&mut self, now: Instant) -> Option<Vec<EnrichedPacket>> {
        if !self.buf.is_empty()
            && now.duration_since(self.last_flush) >= Self::FLUSH_INTERVAL
        {
            self.last_flush = now;
            Some(std::mem::take(&mut self.buf))
        } else {
            None
        }
    }

    fn drain(&mut self) -> Vec<EnrichedPacket> {
        std::mem::take(&mut self.buf)
    }
}
