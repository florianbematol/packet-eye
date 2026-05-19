//! Alert rule definitions, severities, payload types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// User-configurable rule toggles + thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRules {
    /// Master switch.
    pub enabled: bool,
    /// Match against threat lists (Spamhaus, FireHOL, Tor, custom).
    pub threat_list: bool,
    /// Burst toward a single remote IP.
    pub burst: bool,
    pub burst_threshold_pps: u32,
    /// Hits to suspicious destination ports.
    pub suspicious_port: bool,
    pub suspicious_ports: Vec<u16>,
    /// First time we see a given (process, public dst) combination.
    pub new_process_external: bool,
    /// First time we see a given remote ASN.
    pub new_asn: bool,
    /// First time we see a given remote country.
    pub new_country: bool,
}

impl Default for AlertRules {
    fn default() -> Self {
        Self {
            enabled: true,
            threat_list: true,
            burst: true,
            burst_threshold_pps: 500,
            suspicious_port: true,
            suspicious_ports: vec![
                23, // telnet
                445, // SMB
                1337,
                3389, // RDP outbound
                4444,
                5555,
                6666,
                6667, // IRC
                31337,
            ],
            new_process_external: false,
            new_asn: false,
            new_country: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub ts_ms: i64,
    pub severity: Severity,
    /// Stable rule identifier (e.g. "threat-list", "burst").
    pub rule: &'static str,
    /// Human-readable one-liner.
    pub message: String,
    /// Remote IP that triggered the alert, if relevant.
    pub remote_ip: Option<String>,
    /// Optional extra context payload.
    pub context: Option<serde_json::Value>,
}
