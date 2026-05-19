//! Enrichment pipeline.

pub mod dns;
pub mod geoip;
pub mod local_ips;
pub mod process;

use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::capture::types::{Direction, PacketEvent, Protocol};
use dns::DnsResolver;
use geoip::{GeoIpResolver, GeoLookup};
use local_ips::LocalIps;
use process::ProcessResolver;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SideInfo {
    pub geo: Option<GeoLookup>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedPacket {
    pub ts_ms: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: Protocol,
    pub len: u32,
    pub tcp_flags: u8,
    pub direction: Direction,
    pub src: SideInfo,
    pub dst: SideInfo,
    pub process: Option<String>,
    pub pid: Option<u32>,
    /// Hex-encoded prefix of the raw frame (for the UI's hex viewer).
    /// Truncated server-side at 256 bytes.
    #[serde(default)]
    pub payload_hex: Option<String>,
}

pub struct Enricher {
    pub geoip: Arc<GeoIpResolver>,
    pub processes: Arc<ProcessResolver>,
    pub dns: Arc<DnsResolver>,
    pub local: Arc<LocalIps>,
}

impl Enricher {
    pub fn new(
        geoip: Arc<GeoIpResolver>,
        processes: Arc<ProcessResolver>,
        dns: Arc<DnsResolver>,
        local: Arc<LocalIps>,
    ) -> Self {
        Self {
            geoip,
            processes,
            dns,
            local,
        }
    }

    pub fn enrich(&self, p: PacketEvent) -> EnrichedPacket {
        let direction = self.local.classify(&p.src_ip, &p.dst_ip);

        let local_port_proto = match direction {
            Direction::Outbound => Some((p.src_port, p.proto)),
            Direction::Inbound => Some((p.dst_port, p.proto)),
            Direction::Unknown => None,
        };

        let process = local_port_proto
            .and_then(|(port, proto)| self.processes.lookup(port, proto));

        let src_geo = self.geoip.lookup(&p.src_ip);
        let dst_geo = self.geoip.lookup(&p.dst_ip);

        let src_host = self.dns.lookup_or_resolve_async(&p.src_ip);
        let dst_host = self.dns.lookup_or_resolve_async(&p.dst_ip);

        EnrichedPacket {
            ts_ms: p.ts_ms,
            src_ip: p.src_ip,
            dst_ip: p.dst_ip,
            src_port: p.src_port,
            dst_port: p.dst_port,
            proto: p.proto,
            len: p.len,
            tcp_flags: p.tcp_flags,
            direction,
            src: SideInfo { geo: src_geo, hostname: src_host },
            dst: SideInfo { geo: dst_geo, hostname: dst_host },
            process: process.as_ref().map(|p| p.name.clone()),
            pid: process.map(|p| p.pid),
            payload_hex: p.payload_hex,
        }
    }
}
