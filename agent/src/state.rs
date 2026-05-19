//! Shared application state.
//!
//! `AppState` is the single value passed to every axum handler. It holds:
//!   - the enrichment pipeline,
//!   - a tokio broadcast channel to fan out enriched packets to WebSocket
//!     clients,
//!   - a handle on the running capture (if any),
//!   - rolling stats.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::alerts::{Alert, AlertEngine};
use crate::api::self_ip::SelfCache;
use crate::capture::runner::Runner;
use crate::enrich::{EnrichedPacket, Enricher};
use crate::enrich::geoip::GeoIpResolver;

/// Capacity of the live broadcast channel. Old packets are dropped if
/// clients can't keep up — that's fine, we want freshness, not history.
const BROADCAST_CAP: usize = 4096;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct StatsTick {
    pub ts_ms: i64,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
    pub active_connections: u32,
    pub total_packets: u64,
    pub total_bytes: u64,
}

#[derive(Default)]
struct StatsAccumulator {
    last_window_start: Option<Instant>,
    pkts_window: u64,
    bytes_window: u64,
    total_packets: u64,
    total_bytes: u64,
    last_tick: StatsTick,
}

pub struct AppState {
    pub enricher: Arc<Enricher>,
    pub geoip: Arc<GeoIpResolver>,
    pub alerts: Arc<AlertEngine>,
    pub tx: broadcast::Sender<Vec<EnrichedPacket>>,
    pub alert_tx: broadcast::Sender<Vec<Alert>>,
    /// Capture runner; `Some` while a capture is active.
    pub runner: Mutex<Option<Runner>>,
    pub self_cache: Arc<SelfCache>,
    stats: Mutex<StatsAccumulator>,
}

impl AppState {
    pub fn new(
        enricher: Arc<Enricher>,
        geoip: Arc<GeoIpResolver>,
        alerts: Arc<AlertEngine>,
    ) -> Self {
        let (tx, _rx) = broadcast::channel::<Vec<EnrichedPacket>>(BROADCAST_CAP);
        let (alert_tx, _arx) = broadcast::channel::<Vec<Alert>>(256);
        Self {
            enricher,
            geoip,
            alerts,
            tx,
            alert_tx,
            runner: Mutex::new(None),
            self_cache: SelfCache::new(),
            stats: Mutex::new(StatsAccumulator::default()),
        }
    }

    /// Push an enriched batch to all live websocket clients.
    /// Returns the number of subscribers (0 if nobody is listening).
    pub fn publish(&self, batch: Vec<EnrichedPacket>) -> usize {
        let n_pkts = batch.len() as u64;
        let n_bytes: u64 = batch.iter().map(|p| p.len as u64).sum();

        // Update stats counters.
        {
            let mut s = self.stats.lock();
            let now = Instant::now();
            if s.last_window_start.is_none() {
                s.last_window_start = Some(now);
            }
            s.pkts_window += n_pkts;
            s.bytes_window += n_bytes;
            s.total_packets += n_pkts;
            s.total_bytes += n_bytes;

            let elapsed = now.duration_since(s.last_window_start.unwrap());
            if elapsed >= Duration::from_millis(1000) {
                let secs = elapsed.as_secs_f64().max(0.001);
                s.last_tick = StatsTick {
                    ts_ms: time::OffsetDateTime::now_utc()
                        .unix_timestamp_nanos()
                        .div_euclid(1_000_000) as i64,
                    packets_per_sec: s.pkts_window as f64 / secs,
                    bytes_per_sec: s.bytes_window as f64 / secs,
                    active_connections: 0,
                    total_packets: s.total_packets,
                    total_bytes: s.total_bytes,
                };
                s.pkts_window = 0;
                s.bytes_window = 0;
                s.last_window_start = Some(now);
            }
        }

        // Run alert evaluation on each packet (cheap; mostly hash lookups).
        let alerts: Vec<Alert> = batch
            .iter()
            .flat_map(|p| self.alerts.evaluate(p))
            .collect();
        if !alerts.is_empty() {
            let _ = self.alert_tx.send(alerts);
        }

        self.tx.send(batch).unwrap_or(0)
    }

    pub fn current_stats(&self) -> StatsTick {
        self.stats.lock().last_tick
    }

    pub fn is_running(&self) -> bool {
        self.runner.lock().is_some()
    }
}
