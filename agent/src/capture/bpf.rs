//! BPF filter composition.
//!
//! The frontend exposes a small set of high-level toggles
//! (include LAN, include localhost, include broadcast, custom expression).
//! We translate that into a single BPF expression understood by libpcap.
//!
//! BPF reference: https://www.tcpdump.org/manpages/pcap-filter.7.html

use serde::{Deserialize, Serialize};

/// User-facing capture filter options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureFilter {
    /// Include traffic to/from RFC1918 + link-local + IPv6 ULA/link-local.
    #[serde(default)]
    pub include_lan: bool,
    /// Include 127.0.0.0/8 and ::1.
    #[serde(default)]
    pub include_localhost: bool,
    /// Include broadcast and multicast traffic.
    #[serde(default)]
    pub include_broadcast: bool,
    /// Optional raw BPF expression appended (with AND) to the computed one.
    #[serde(default)]
    pub custom: Option<String>,
}

impl Default for CaptureFilter {
    fn default() -> Self {
        // Defaults to "capture everything" — same vibe as Wireshark.
        // The UI exposes the toggles for users who want a quieter feed.
        Self {
            include_lan: true,
            include_localhost: true,
            include_broadcast: true,
            custom: None,
        }
    }
}

impl CaptureFilter {
    /// Build the final BPF expression. Empty string means "capture everything".
    pub fn to_bpf(&self) -> String {
        let mut clauses: Vec<String> = Vec::new();

        // No protocol pre-filter: we now let ARP, ICMPv6 NDP and other
        // non-IP payloads through, just like Wireshark does by default.
        // The exclusion clauses below only apply to packets that *do*
        // carry an IP layer, so non-IP frames are always visible.

        if !self.include_localhost {
            // Exclude loopback subnets (only meaningful on IP frames).
            clauses.push(
                "not (ip and net 127.0.0.0/8) and not (ip6 and host ::1)".to_string(),
            );
        }

        if !self.include_lan {
            // Exclude RFC1918 + link-local on both ends — only meaningful
            // on IP frames; ARP/etc. always pass through.
            clauses.push(
                "not (ip and net 10.0.0.0/8) and \
                 not (ip and net 172.16.0.0/12) and \
                 not (ip and net 192.168.0.0/16) and \
                 not (ip and net 169.254.0.0/16) and \
                 not (ip6 and net fe80::/10) and \
                 not (ip6 and net fc00::/7)"
                    .to_string(),
            );
        }

        if !self.include_broadcast {
            // 255.255.255.255 broadcast + IPv4 multicast 224/4 + IPv6 ff00::/8
            clauses.push(
                "not (ip and host 255.255.255.255) and \
                 not (ip and net 224.0.0.0/4) and \
                 not (ip6 and net ff00::/8)"
                    .to_string(),
            );
        }

        if let Some(c) = &self.custom {
            let trimmed = c.trim();
            if !trimmed.is_empty() {
                clauses.push(format!("({})", trimmed));
            }
        }

        clauses.join(" and ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_excludes_lan_loopback_broadcast() {
        let f = CaptureFilter::default();
        let bpf = f.to_bpf();
        assert!(bpf.contains("net 127.0.0.0/8"));
        assert!(bpf.contains("net 10.0.0.0/8"));
        assert!(bpf.contains("net 224.0.0.0/4"));
    }

    #[test]
    fn including_lan_drops_rfc1918_clause() {
        let mut f = CaptureFilter::default();
        f.include_lan = true;
        let bpf = f.to_bpf();
        assert!(!bpf.contains("net 10.0.0.0/8"));
    }

    #[test]
    fn custom_is_appended() {
        let mut f = CaptureFilter::default();
        f.custom = Some("tcp port 443".into());
        let bpf = f.to_bpf();
        assert!(bpf.ends_with("(tcp port 443)"));
    }
}
