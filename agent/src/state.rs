//! Shared application state.
//!
//! `AppState` is the single value passed to every axum handler. It holds:
//!   - the enrichment pipeline,
//!   - a tokio broadcast channel to fan out enriched packets to WebSocket
//!     clients,
//!   - a handle on the running capture (if any),
//!   - rolling stats.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::alerts::{Alert, AlertEngine};
use crate::api::self_ip::SelfCache;
use crate::capture::pcap_ring::PcapRing;
use crate::capture::runner::Runner;
use crate::enrich::{EnrichedPacket, Enricher};
use crate::enrich::geoip::GeoIpResolver;
use crate::history::History;
use crate::threats::ThreatMatcher;

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
    /// Whether a capture is active (lets clients notice a capture that
    /// died on its own).
    pub running: bool,
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
    pub threats: Arc<ThreatMatcher>,
    pub pcap: Arc<PcapRing>,
    pub history: Arc<History>,
    pub tx: broadcast::Sender<Vec<EnrichedPacket>>,
    pub alert_tx: broadcast::Sender<Vec<Alert>>,
    /// Capture runner; `Some` while a capture is active.
    pub runner: Mutex<Option<Runner>>,
    /// Serialises start/stop so two concurrent requests can't both
    /// spawn a capture.
    pub capture_op: tokio::sync::Mutex<()>,
    pub self_cache: Arc<SelfCache>,
    stats: Mutex<StatsAccumulator>,
}

impl AppState {
    pub fn new(
        enricher: Arc<Enricher>,
        geoip: Arc<GeoIpResolver>,
        alerts: Arc<AlertEngine>,
        threats: Arc<ThreatMatcher>,
        pcap: Arc<PcapRing>,
        history: Arc<History>,
    ) -> Self {
        let (tx, _rx) = broadcast::channel::<Vec<EnrichedPacket>>(BROADCAST_CAP);
        let (alert_tx, _arx) = broadcast::channel::<Vec<Alert>>(256);
        Self {
            enricher,
            geoip,
            alerts,
            threats,
            pcap,
            history,
            tx,
            alert_tx,
            runner: Mutex::new(None),
            capture_op: tokio::sync::Mutex::new(()),
            self_cache: SelfCache::new(),
            stats: Mutex::new(StatsAccumulator::default()),
        }
    }

    /// Push an enriched batch to all live websocket clients.
    /// Returns the number of subscribers (0 if nobody is listening).
    pub fn publish(&self, batch: Vec<EnrichedPacket>) -> usize {
        let n_pkts = batch.len() as u64;
        let n_bytes: u64 = batch.iter().map(|p| p.len as u64).sum();

        // Update stats counters (rates are computed by `tick_stats`).
        {
            let mut s = self.stats.lock();
            s.pkts_window += n_pkts;
            s.bytes_window += n_bytes;
            s.total_packets += n_pkts;
            s.total_bytes += n_bytes;
        }

        // Run alert evaluation on each packet (cheap; mostly hash lookups).
        let alerts: Vec<Alert> = batch
            .iter()
            .flat_map(|p| self.alerts.evaluate(p))
            .collect();
        if !alerts.is_empty() {
            self.history.record_alerts(&alerts);
            let _ = self.alert_tx.send(alerts);
        }

        // Fold into the per-minute history aggregate (flushed periodically).
        self.history.record(&batch);

        self.tx.send(batch).unwrap_or(0)
    }

    /// Close the current rate window. Called every second by a timer, so
    /// rates drop to zero when traffic stops instead of freezing.
    pub fn tick_stats(&self) {
        let running = self.is_running();
        let mut s = self.stats.lock();
        let now = Instant::now();
        let start = *s.last_window_start.get_or_insert(now);
        let secs = now.duration_since(start).as_secs_f64();
        if secs < 0.001 {
            return;
        }
        s.last_tick = StatsTick {
            ts_ms: time::OffsetDateTime::now_utc()
                .unix_timestamp_nanos()
                .div_euclid(1_000_000) as i64,
            packets_per_sec: s.pkts_window as f64 / secs,
            bytes_per_sec: s.bytes_window as f64 / secs,
            active_connections: 0,
            total_packets: s.total_packets,
            total_bytes: s.total_bytes,
            running,
        };
        s.pkts_window = 0;
        s.bytes_window = 0;
        s.last_window_start = Some(now);
    }

    pub fn current_stats(&self) -> StatsTick {
        StatsTick {
            running: self.is_running(),
            ..self.stats.lock().last_tick
        }
    }

    /// Is a capture active? Also reaps a runner whose thread exited on
    /// its own (device unplugged, repeated pcap errors).
    pub fn is_running(&self) -> bool {
        let mut runner = self.runner.lock();
        if runner.as_ref().is_some_and(|r| r.is_finished()) {
            tracing::warn!("capture thread exited unexpectedly");
            // The thread is already gone, so dropping (= joining) is instant.
            *runner = None;
        }
        runner.is_some()
    }
}
