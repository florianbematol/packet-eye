//! The alert engine. Stateful: keeps per-IP burst counters + sets of
//! "things we've seen already" (ASNs, countries, process-IP pairs).

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};

use crate::capture::types::Direction;
use crate::enrich::EnrichedPacket;
use crate::threats::ThreatMatcher;

use super::rules::{Alert, AlertRules, Severity};

/// Per-IP burst tracker: rolling count over 1s.
#[derive(Default)]
struct BurstSlot {
    window_start: Option<Instant>,
    count: u32,
    last_alert_at: Option<Instant>,
}

pub struct AlertEngine {
    rules: RwLock<AlertRules>,
    threats: Arc<ThreatMatcher>,
    burst: DashMap<IpAddr, BurstSlot>,
    seen_asns: Mutex<HashSet<u32>>,
    seen_countries: Mutex<HashSet<String>>,
    seen_proc_ip: Mutex<HashSet<(String, IpAddr)>>,
    rules_path: PathBuf,
}

impl AlertEngine {
    pub fn new(threats: Arc<ThreatMatcher>) -> Arc<Self> {
        let rules_path = rules_file_path();
        let rules = load_rules_or_default(&rules_path);
        Arc::new(Self {
            rules: RwLock::new(rules),
            threats,
            burst: DashMap::new(),
            seen_asns: Mutex::new(HashSet::new()),
            seen_countries: Mutex::new(HashSet::new()),
            seen_proc_ip: Mutex::new(HashSet::new()),
            rules_path,
        })
    }

    pub fn rules(&self) -> AlertRules {
        self.rules.read().clone()
    }

    pub fn set_rules(&self, new_rules: AlertRules) {
        *self.rules.write() = new_rules.clone();
        let _ = save_rules(&self.rules_path, &new_rules);
    }

    pub fn threat_count(&self) -> usize {
        self.threats.len()
    }

    /// Evaluate one enriched packet. Returns 0..N alerts.
    pub fn evaluate(&self, p: &EnrichedPacket) -> Vec<Alert> {
        let rules = self.rules.read().clone();
        if !rules.enabled {
            return Vec::new();
        }

        let mut out = Vec::new();
        let now = Instant::now();

        // Determine the "remote" side once.
        let (remote_ip, remote_port) = match p.direction {
            Direction::Outbound => (p.dst_ip, p.dst_port),
            Direction::Inbound => (p.src_ip, p.src_port),
            Direction::Unknown => (p.dst_ip, p.dst_port),
        };
        let remote_geo = match p.direction {
            Direction::Outbound | Direction::Unknown => p.dst.geo.as_ref(),
            Direction::Inbound => p.src.geo.as_ref(),
        };

        // Skip every alert rule when the "remote" side is actually a
        // private / loopback / link-local / multicast address. Threat
        // lists routinely include those ranges as bogons (e.g. FireHOL
        // tagging 192.168.0.0/16) but on a LAN they correspond to
        // perfectly normal hosts (your gateway, printers, etc.) and
        // alerting on them is just noise.
        if !is_routable_public(&remote_ip) {
            return out;
        }

        // 1. Threat list -------------------------------------------------
        if rules.threat_list {
            if let Some(verdict) = self.threats.lookup(&remote_ip) {
                out.push(Alert {
                    ts_ms: p.ts_ms,
                    severity: Severity::Critical,
                    rule: "threat-list",
                    message: format!(
                        "{} is on {}",
                        remote_ip,
                        verdict.label
                    ),
                    remote_ip: Some(remote_ip.to_string()),
                    context: Some(serde_json::json!({
                        "list": verdict.list,
                        "process": p.process,
                    })),
                });
            }
        }

        // 2. Suspicious port --------------------------------------------
        if rules.suspicious_port
            && p.direction == Direction::Outbound
            && rules.suspicious_ports.contains(&remote_port)
        {
            out.push(Alert {
                ts_ms: p.ts_ms,
                severity: Severity::Medium,
                rule: "suspicious-port",
                message: format!(
                    "{} -> {}:{} (suspicious port)",
                    p.process.as_deref().unwrap_or("unknown"),
                    remote_ip,
                    remote_port
                ),
                remote_ip: Some(remote_ip.to_string()),
                context: Some(serde_json::json!({"port": remote_port})),
            });
        }

        // 3. Burst -------------------------------------------------------
        if rules.burst {
            let mut entry = self.burst.entry(remote_ip).or_default();
            let slot = entry.value_mut();
            let reset = slot
                .window_start
                .map(|t| now.duration_since(t).as_millis() >= 1000)
                .unwrap_or(true);
            if reset {
                slot.window_start = Some(now);
                slot.count = 0;
            }
            slot.count += 1;
            if slot.count >= rules.burst_threshold_pps {
                let recently_alerted = slot
                    .last_alert_at
                    .map(|t| now.duration_since(t).as_millis() < 5000)
                    .unwrap_or(false);
                if !recently_alerted {
                    slot.last_alert_at = Some(now);
                    out.push(Alert {
                        ts_ms: p.ts_ms,
                        severity: Severity::High,
                        rule: "burst",
                        message: format!(
                            "{} pkt/s toward {}",
                            slot.count, remote_ip
                        ),
                        remote_ip: Some(remote_ip.to_string()),
                        context: Some(serde_json::json!({
                            "pps": slot.count,
                            "threshold": rules.burst_threshold_pps,
                        })),
                    });
                }
            }
        }

        // 4. New ASN -----------------------------------------------------
        if rules.new_asn {
            if let Some(asn) = remote_geo.and_then(|g| g.asn) {
                let mut set = self.seen_asns.lock();
                if !set.contains(&asn) {
                    set.insert(asn);
                    let org = remote_geo
                        .and_then(|g| g.asn_org.clone())
                        .unwrap_or_default();
                    out.push(Alert {
                        ts_ms: p.ts_ms,
                        severity: Severity::Info,
                        rule: "new-asn",
                        message: format!("first connection to AS{asn} {org}"),
                        remote_ip: Some(remote_ip.to_string()),
                        context: Some(serde_json::json!({
                            "asn": asn, "org": org,
                        })),
                    });
                }
            }
        }

        // 5. New country -------------------------------------------------
        if rules.new_country {
            if let Some(country) =
                remote_geo.and_then(|g| g.country_iso.clone())
            {
                let mut set = self.seen_countries.lock();
                if !set.contains(&country) {
                    set.insert(country.clone());
                    out.push(Alert {
                        ts_ms: p.ts_ms,
                        severity: Severity::Info,
                        rule: "new-country",
                        message: format!(
                            "first connection to {country}"
                        ),
                        remote_ip: Some(remote_ip.to_string()),
                        context: Some(serde_json::json!({
                            "country": country,
                        })),
                    });
                }
            }
        }

        // 6. New process / external IP combination ----------------------
        if rules.new_process_external && p.direction == Direction::Outbound {
            if let Some(proc_name) = &p.process {
                if remote_geo.is_some() {
                    let key = (proc_name.clone(), remote_ip);
                    let mut set = self.seen_proc_ip.lock();
                    if !set.contains(&key) {
                        set.insert(key);
                        out.push(Alert {
                            ts_ms: p.ts_ms,
                            severity: Severity::Low,
                            rule: "new-process-external",
                            message: format!(
                                "{} -> {} (new external endpoint)",
                                proc_name, remote_ip
                            ),
                            remote_ip: Some(remote_ip.to_string()),
                            context: Some(serde_json::json!({
                                "process": proc_name,
                            })),
                        });
                    }
                }
            }
        }

        out
    }
}

fn rules_file_path() -> PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("dev", "packet-eye", "packet-eye") {
        let dir = dirs.config_dir();
        let _ = std::fs::create_dir_all(dir);
        return dir.join("alert-rules.json");
    }
    PathBuf::from("alert-rules.json")
}

fn load_rules_or_default(path: &std::path::Path) -> AlertRules {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<AlertRules>(&bytes) {
            Ok(r) => {
                tracing::info!("alert rules loaded from {}", path.display());
                r
            }
            Err(e) => {
                tracing::warn!("alert-rules.json invalid ({e}); using defaults");
                AlertRules::default()
            }
        },
        Err(_) => AlertRules::default(),
    }
}

fn save_rules(path: &std::path::Path, rules: &AlertRules) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(rules)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, json)
}

/// Returns true iff `ip` is a globally-routable public address. Filters
/// out RFC1918 private space, loopback, link-local, multicast, broadcast,
/// CGNAT, IPv6 ULA / link-local / multicast — none of which can be a
/// real external threat regardless of what a third-party block list
/// claims.
fn is_routable_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                // RFC1918 private
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                // Carrier-grade NAT
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                // 0.0.0.0/8 "this network"
                || o[0] == 0
                // 192.0.0.0/24 IETF protocol assignments + 192.0.2.0/24 docs
                || (o[0] == 192 && o[1] == 0)
                // 198.18.0.0/15 benchmarking
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                // 198.51.100.0/24 + 203.0.113.0/24 docs
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                // 240.0.0.0/4 reserved
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique-local fc00::/7
                || (seg0 & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (seg0 & 0xffc0) == 0xfe80)
        }
    }
}
