//! Persistent traffic history (SQLite).
//!
//! Live packets are aggregated in memory per *minute × flow* and flushed
//! to disk every few seconds, so the database grows with the number of
//! distinct flows per minute — not with the packet rate. Alerts are
//! stored too. Old rows are purged according to `retention_days`.
//!
//! File: `%APPDATA%\packet-eye\packet-eye\data\history.sqlite`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::alerts::Alert;
use crate::capture::types::{Direction, Protocol};
use crate::enrich::EnrichedPacket;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySettings {
    pub enabled: bool,
    pub retention_days: u32,
}

impl Default for HistorySettings {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 7,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    minute: i64,
    proto: &'static str,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
}

#[derive(Debug, Clone, Default)]
struct FlowAgg {
    direction: &'static str,
    process: Option<String>,
    domain: Option<String>,
    country_iso: Option<String>,
    city: Option<String>,
    asn: Option<u32>,
    asn_org: Option<String>,
    packets: u64,
    bytes: u64,
}

pub struct History {
    conn: Mutex<Connection>,
    path: PathBuf,
    settings: RwLock<HistorySettings>,
    settings_path: PathBuf,
    pending_flows: Mutex<HashMap<FlowKey, FlowAgg>>,
    pending_alerts: Mutex<Vec<Alert>>,
}

// ---- Query result types --------------------------------------------

#[derive(Debug, Serialize)]
pub struct TimelinePoint {
    pub ts: i64,
    pub packets: u64,
    pub bytes: u64,
    pub endpoints: u64,
}

#[derive(Debug, Serialize)]
pub struct FlowRow {
    pub proto: String,
    pub direction: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub process: Option<String>,
    pub domain: Option<String>,
    pub country_iso: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Serialize)]
pub struct AppRow {
    pub process: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub endpoints: u64,
    pub countries: Vec<String>,
    pub domains: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Serialize)]
pub struct AlertRow {
    pub ts_ms: i64,
    pub severity: String,
    pub rule: String,
    pub message: String,
    pub remote_ip: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HistoryInfo {
    pub path: String,
    pub size_bytes: u64,
    pub flow_rows: u64,
    pub alert_rows: u64,
    pub oldest_ts: Option<i64>,
    pub newest_ts: Option<i64>,
    pub settings: HistorySettings,
}

#[derive(Debug, Default, Deserialize)]
pub struct RangeQuery {
    /// Unix seconds (inclusive). Defaults to 24 h ago.
    pub from: Option<i64>,
    /// Unix seconds (inclusive). Defaults to now.
    pub to: Option<i64>,
    pub limit: Option<u32>,
    /// Free-text filter (IP, domain, process, ASN org, country).
    pub q: Option<String>,
    /// Restrict to one process name.
    pub process: Option<String>,
    /// Timeline bucket size in seconds (min 60).
    pub bucket: Option<i64>,
}

impl RangeQuery {
    fn bounds(&self) -> (i64, i64) {
        let now = now_secs();
        let to = self.to.unwrap_or(now);
        let from = self.from.unwrap_or(to - 86_400);
        (from.min(to), to)
    }
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(200).clamp(1, 5000) as i64
    }
    fn like(&self) -> Option<String> {
        self.q
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{}%", s.replace('%', "").replace('_', "")))
    }
}

pub fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn proto_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::Other => "other",
    }
}

fn dir_str(d: Direction) -> &'static str {
    match d {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
        Direction::Unknown => "unknown",
    }
}

fn data_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "packet-eye", "packet-eye")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn config_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "packet-eye", "packet-eye")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

impl History {
    /// Open (or create) the default history database.
    pub fn open_default() -> Result<Arc<Self>> {
        let dir = data_dir();
        std::fs::create_dir_all(&dir).ok();
        let cfg = config_dir();
        std::fs::create_dir_all(&cfg).ok();
        Self::open(dir.join("history.sqlite"), cfg.join("history.json"))
    }

    pub fn open(path: PathBuf, settings_path: PathBuf) -> Result<Arc<Self>> {
        let conn = Connection::open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS flows (
                 minute      INTEGER NOT NULL,
                 proto       TEXT    NOT NULL,
                 direction   TEXT    NOT NULL,
                 local_ip    TEXT    NOT NULL,
                 local_port  INTEGER NOT NULL,
                 remote_ip   TEXT    NOT NULL,
                 remote_port INTEGER NOT NULL,
                 process     TEXT,
                 domain      TEXT,
                 country_iso TEXT,
                 city        TEXT,
                 asn         INTEGER,
                 asn_org     TEXT,
                 packets     INTEGER NOT NULL,
                 bytes       INTEGER NOT NULL,
                 PRIMARY KEY (minute, proto, local_ip, local_port, remote_ip, remote_port)
             );
             CREATE INDEX IF NOT EXISTS flows_by_process ON flows(process, minute);
             CREATE INDEX IF NOT EXISTS flows_by_remote ON flows(remote_ip, minute);
             CREATE TABLE IF NOT EXISTS alerts (
                 ts_ms     INTEGER NOT NULL,
                 severity  TEXT    NOT NULL,
                 rule      TEXT    NOT NULL,
                 message   TEXT    NOT NULL,
                 remote_ip TEXT
             );
             CREATE INDEX IF NOT EXISTS alerts_by_ts ON alerts(ts_ms);",
        )?;
        let settings = std::fs::read(&settings_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        tracing::info!("history database: {}", path.display());
        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
            path,
            settings: RwLock::new(settings),
            settings_path,
            pending_flows: Mutex::new(HashMap::new()),
            pending_alerts: Mutex::new(Vec::new()),
        }))
    }

    pub fn settings(&self) -> HistorySettings {
        self.settings.read().clone()
    }

    pub fn set_settings(&self, s: HistorySettings) -> Result<HistorySettings> {
        let s = HistorySettings {
            enabled: s.enabled,
            retention_days: s.retention_days.clamp(1, 365),
        };
        std::fs::write(&self.settings_path, serde_json::to_vec_pretty(&s)?)?;
        *self.settings.write() = s.clone();
        Ok(s)
    }

    /// Fold a batch of live packets into the in-memory aggregate.
    pub fn record(&self, batch: &[EnrichedPacket]) {
        if !self.settings.read().enabled {
            return;
        }
        let mut pending = self.pending_flows.lock();
        for p in batch {
            if p.src_ip.is_unspecified() && p.dst_ip.is_unspecified() {
                continue; // non-IP frames (ARP…)
            }
            let (rip, rport, geo) = p.remote();
            let (lip, lport) = p.local();
            let key = FlowKey {
                minute: (p.ts_ms / 1000).div_euclid(60) * 60,
                proto: proto_str(p.proto),
                local_ip: lip.to_string(),
                local_port: lport,
                remote_ip: rip.to_string(),
                remote_port: rport,
            };
            let e = pending.entry(key).or_default();
            e.packets += 1;
            e.bytes += p.len as u64;
            if p.direction != Direction::Unknown || e.direction.is_empty() {
                e.direction = dir_str(p.direction);
            }
            if e.process.is_none() {
                e.process = p.process.clone();
            }
            if p.domain.is_some() {
                e.domain = p.domain.clone();
            }
            if let Some(g) = geo {
                if e.country_iso.is_none() {
                    e.country_iso = g.country_iso.clone();
                    e.city = g.city.clone();
                    e.asn = g.asn;
                    e.asn_org = g.asn_org.clone();
                }
            }
        }
    }

    pub fn record_alerts(&self, alerts: &[Alert]) {
        if !self.settings.read().enabled {
            return;
        }
        self.pending_alerts.lock().extend(alerts.iter().cloned());
    }

    /// Write the pending aggregate to disk (blocking).
    pub fn flush(&self) -> Result<usize> {
        let flows = std::mem::take(&mut *self.pending_flows.lock());
        let alerts = std::mem::take(&mut *self.pending_alerts.lock());
        if flows.is_empty() && alerts.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        {
            let mut up = tx.prepare_cached(
                "INSERT INTO flows (minute, proto, direction, local_ip, local_port,
                                    remote_ip, remote_port, process, domain,
                                    country_iso, city, asn, asn_org, packets, bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
                 ON CONFLICT (minute, proto, local_ip, local_port, remote_ip, remote_port)
                 DO UPDATE SET
                     packets = packets + excluded.packets,
                     bytes   = bytes   + excluded.bytes,
                     process = COALESCE(process, excluded.process),
                     domain  = COALESCE(excluded.domain, domain),
                     country_iso = COALESCE(country_iso, excluded.country_iso),
                     city    = COALESCE(city, excluded.city),
                     asn     = COALESCE(asn, excluded.asn),
                     asn_org = COALESCE(asn_org, excluded.asn_org)",
            )?;
            for (k, v) in &flows {
                up.execute(params![
                    k.minute,
                    k.proto,
                    v.direction,
                    k.local_ip,
                    k.local_port,
                    k.remote_ip,
                    k.remote_port,
                    v.process,
                    v.domain,
                    v.country_iso,
                    v.city,
                    v.asn,
                    v.asn_org,
                    v.packets as i64,
                    v.bytes as i64,
                ])?;
            }
            let mut ins = tx.prepare_cached(
                "INSERT INTO alerts (ts_ms, severity, rule, message, remote_ip)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for a in &alerts {
                ins.execute(params![a.ts_ms, a.severity.as_str(), a.rule, a.message, a.remote_ip])?;
            }
        }
        tx.commit()?;
        Ok(flows.len() + alerts.len())
    }

    /// Delete rows older than the retention window (blocking).
    pub fn purge(&self) -> Result<usize> {
        let days = self.settings.read().retention_days as i64;
        let cutoff = now_secs() - days * 86_400;
        let conn = self.conn.lock();
        let a = conn.execute("DELETE FROM flows WHERE minute < ?1", params![cutoff])?;
        let b = conn.execute("DELETE FROM alerts WHERE ts_ms < ?1", params![cutoff * 1000])?;
        Ok(a + b)
    }

    pub fn clear(&self) -> Result<()> {
        self.pending_flows.lock().clear();
        self.pending_alerts.lock().clear();
        let conn = self.conn.lock();
        conn.execute_batch("DELETE FROM flows; DELETE FROM alerts; VACUUM;")?;
        Ok(())
    }

    pub fn info(&self) -> Result<HistoryInfo> {
        let conn = self.conn.lock();
        let (flow_rows, oldest, newest): (i64, Option<i64>, Option<i64>) = conn.query_row(
            "SELECT COUNT(*), MIN(minute), MAX(minute) FROM flows",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let alert_rows: i64 = conn.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))?;
        let size = ["", "-wal"]
            .iter()
            .filter_map(|s| std::fs::metadata(format!("{}{s}", self.path.display())).ok())
            .map(|m| m.len())
            .sum();
        Ok(HistoryInfo {
            path: self.path.display().to_string(),
            size_bytes: size,
            flow_rows: flow_rows as u64,
            alert_rows: alert_rows as u64,
            oldest_ts: oldest,
            newest_ts: newest,
            settings: self.settings(),
        })
    }

    pub fn timeline(&self, q: &RangeQuery) -> Result<Vec<TimelinePoint>> {
        let (from, to) = q.bounds();
        let bucket = q.bucket.unwrap_or_else(|| auto_bucket(to - from)).max(60);
        let conn = self.conn.lock();
        let mut st = conn.prepare_cached(
            "SELECT (minute / ?3) * ?3 AS t, SUM(packets), SUM(bytes), COUNT(DISTINCT remote_ip)
             FROM flows
             WHERE minute BETWEEN ?1 AND ?2 AND (?4 IS NULL OR process = ?4)
             GROUP BY t ORDER BY t",
        )?;
        let rows = st
            .query_map(params![from, to, bucket, q.process.as_deref()], |r| {
                Ok(TimelinePoint {
                    ts: r.get(0)?,
                    packets: r.get::<_, i64>(1)? as u64,
                    bytes: r.get::<_, i64>(2)? as u64,
                    endpoints: r.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn flows(&self, q: &RangeQuery) -> Result<Vec<FlowRow>> {
        let (from, to) = q.bounds();
        let conn = self.conn.lock();
        let mut st = conn.prepare_cached(
            "SELECT proto, MAX(direction), remote_ip, remote_port, MAX(process), MAX(domain),
                    MAX(country_iso), MAX(city), MAX(asn), MAX(asn_org),
                    SUM(packets), SUM(bytes), MIN(minute), MAX(minute)
             FROM flows
             WHERE minute BETWEEN ?1 AND ?2
               AND (?3 IS NULL OR process = ?3)
               AND (?4 IS NULL OR remote_ip LIKE ?4 OR domain LIKE ?4 OR process LIKE ?4
                    OR asn_org LIKE ?4 OR country_iso LIKE ?4 OR city LIKE ?4)
             GROUP BY proto, remote_ip, remote_port, process
             ORDER BY SUM(bytes) DESC
             LIMIT ?5",
        )?;
        let rows = st
            .query_map(params![from, to, q.process.as_deref(), q.like(), q.limit()], |r| {
                Ok(FlowRow {
                    proto: r.get(0)?,
                    direction: r.get(1)?,
                    remote_ip: r.get(2)?,
                    remote_port: r.get(3)?,
                    process: r.get(4)?,
                    domain: r.get(5)?,
                    country_iso: r.get(6)?,
                    city: r.get(7)?,
                    asn: r.get(8)?,
                    asn_org: r.get(9)?,
                    packets: r.get::<_, i64>(10)? as u64,
                    bytes: r.get::<_, i64>(11)? as u64,
                    first_seen: r.get(12)?,
                    last_seen: r.get::<_, i64>(13)? + 59,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn apps(&self, q: &RangeQuery) -> Result<Vec<AppRow>> {
        let (from, to) = q.bounds();
        let conn = self.conn.lock();
        let mut st = conn.prepare_cached(
            "SELECT process, SUM(packets), SUM(bytes), COUNT(DISTINCT remote_ip),
                    GROUP_CONCAT(DISTINCT country_iso), GROUP_CONCAT(DISTINCT domain),
                    MIN(minute), MAX(minute)
             FROM flows
             WHERE minute BETWEEN ?1 AND ?2
             GROUP BY process
             ORDER BY SUM(bytes) DESC
             LIMIT ?3",
        )?;
        let split = |s: Option<String>, max: usize| -> Vec<String> {
            s.map(|s| s.split(',').take(max).map(str::to_string).collect())
                .unwrap_or_default()
        };
        let rows = st
            .query_map(params![from, to, q.limit()], |r| {
                Ok(AppRow {
                    process: r.get(0)?,
                    packets: r.get::<_, i64>(1)? as u64,
                    bytes: r.get::<_, i64>(2)? as u64,
                    endpoints: r.get::<_, i64>(3)? as u64,
                    countries: split(r.get(4)?, 64),
                    domains: split(r.get(5)?, 12),
                    first_seen: r.get(6)?,
                    last_seen: r.get::<_, i64>(7)? + 59,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn alerts(&self, q: &RangeQuery) -> Result<Vec<AlertRow>> {
        let (from, to) = q.bounds();
        let conn = self.conn.lock();
        let mut st = conn.prepare_cached(
            "SELECT ts_ms, severity, rule, message, remote_ip FROM alerts
             WHERE ts_ms BETWEEN ?1 AND ?2
             ORDER BY ts_ms DESC LIMIT ?3",
        )?;
        let rows = st
            .query_map(params![from * 1000, to * 1000 + 999, q.limit()], |r| {
                Ok(AlertRow {
                    ts_ms: r.get(0)?,
                    severity: r.get(1)?,
                    rule: r.get(2)?,
                    message: r.get(3)?,
                    remote_ip: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Most recent known process name for a remote IP (used to annotate).
    #[allow(dead_code)]
    pub fn last_process_for(&self, ip: &str) -> Option<String> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT process FROM flows WHERE remote_ip = ?1 AND process IS NOT NULL
             ORDER BY minute DESC LIMIT 1",
            params![ip],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }
}

/// Pick a bucket that yields roughly 60–200 points for the range.
fn auto_bucket(span: i64) -> i64 {
    const STEPS: &[i64] = &[60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 86_400];
    for &s in STEPS {
        if span / s <= 200 {
            return s;
        }
    }
    86_400
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::SideInfo;

    fn pkt(ts_ms: i64, remote: &str, len: u32, process: &str) -> EnrichedPacket {
        EnrichedPacket {
            ts_ms,
            src_ip: "192.168.1.2".parse().unwrap(),
            dst_ip: remote.parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
            proto: Protocol::Tcp,
            len,
            tcp_flags: 0,
            direction: Direction::Outbound,
            src: SideInfo::default(),
            dst: SideInfo::default(),
            process: Some(process.into()),
            pid: Some(1),
            domain: Some("example.com".into()),
            domain_source: None,
            payload_hex: None,
        }
    }

    fn temp_history() -> Arc<History> {
        let dir = std::env::temp_dir().join(format!(
            "pe-hist-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        History::open(dir.join("h.sqlite"), dir.join("h.json")).unwrap()
    }

    #[test]
    fn aggregates_per_minute_and_queries() {
        let h = temp_history();
        let t0 = now_secs() * 1000;
        h.record(&[
            pkt(t0, "1.1.1.1", 100, "chrome.exe"),
            pkt(t0 + 10, "1.1.1.1", 50, "chrome.exe"),
            pkt(t0, "8.8.8.8", 10, "game.exe"),
        ]);
        h.flush().unwrap();
        // Same flow again in the same minute: must be summed, not duplicated.
        h.record(&[pkt(t0 + 20, "1.1.1.1", 25, "chrome.exe")]);
        h.flush().unwrap();

        let q = RangeQuery::default();
        let flows = h.flows(&q).unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].remote_ip, "1.1.1.1");
        assert_eq!(flows[0].bytes, 175);
        assert_eq!(flows[0].packets, 3);

        let apps = h.apps(&q).unwrap();
        assert_eq!(apps[0].process.as_deref(), Some("chrome.exe"));
        assert_eq!(apps[0].endpoints, 1);

        let tl = h.timeline(&q).unwrap();
        assert_eq!(tl.iter().map(|p| p.bytes).sum::<u64>(), 185);

        let filtered = h
            .flows(&RangeQuery { q: Some("game".into()), ..Default::default() })
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].remote_ip, "8.8.8.8");

        assert_eq!(h.info().unwrap().flow_rows, 2);
        h.clear().unwrap();
        assert_eq!(h.info().unwrap().flow_rows, 0);
    }
}
