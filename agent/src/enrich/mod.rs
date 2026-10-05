//! Enrichment pipeline.

pub mod domains;
pub mod geoip;
pub mod local_ips;
pub mod process;

use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::capture::types::{Direction, PacketEvent, Protocol};
use domains::{DomainSniffer, DomainSource};
use geoip::{GeoIpResolver, GeoLookup};
use local_ips::LocalIps;
use process::ProcessResolver;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SideInfo {
    pub geo: Option<GeoLookup>,
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
    /// Domain of the remote endpoint, learned from TLS SNI, HTTP `Host`
    /// or DNS answers seen on the wire.
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub domain_source: Option<DomainSource>,
    /// Hex-encoded prefix of the raw frame (for the UI's hex viewer).
    /// Truncated server-side at 256 bytes.
    #[serde(default)]
    pub payload_hex: Option<String>,
}

impl EnrichedPacket {
    /// The remote side of the packet: `(ip, port, geo)`. Mirrors the
    /// frontend's `pickRemote`.
    pub fn remote(&self) -> (IpAddr, u16, Option<&GeoLookup>) {
        match self.direction {
            Direction::Outbound => (self.dst_ip, self.dst_port, self.dst.geo.as_ref()),
            Direction::Inbound => (self.src_ip, self.src_port, self.src.geo.as_ref()),
            Direction::Unknown => {
                if self.src.geo.is_some() && self.dst.geo.is_none() {
                    (self.src_ip, self.src_port, self.src.geo.as_ref())
                } else {
                    (self.dst_ip, self.dst_port, self.dst.geo.as_ref())
                }
            }
        }
    }

    /// The local side of the packet: `(ip, port)`.
    pub fn local(&self) -> (IpAddr, u16) {
        let (rip, rport, _) = self.remote();
        if rip == self.dst_ip && rport == self.dst_port {
            (self.src_ip, self.src_port)
        } else {
            (self.dst_ip, self.dst_port)
        }
    }
}

pub struct Enricher {
    pub geoip: Arc<GeoIpResolver>,
    pub processes: Arc<ProcessResolver>,
    pub domains: Arc<DomainSniffer>,
    pub local: Arc<LocalIps>,
}

impl Enricher {
    pub fn new(
        geoip: Arc<GeoIpResolver>,
        processes: Arc<ProcessResolver>,
        domains: Arc<DomainSniffer>,
        local: Arc<LocalIps>,
    ) -> Self {
        Self {
            geoip,
            processes,
            domains,
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

        let mut out = EnrichedPacket {
            ts_ms: p.ts_ms,
            src_ip: p.src_ip,
            dst_ip: p.dst_ip,
            src_port: p.src_port,
            dst_port: p.dst_port,
            proto: p.proto,
            len: p.len,
            tcp_flags: p.tcp_flags,
            direction,
            src: SideInfo { geo: src_geo },
            dst: SideInfo { geo: dst_geo },
            process: process.as_ref().map(|p| p.name.clone()),
            pid: process.map(|p| p.pid),
            domain: None,
            domain_source: None,
            payload_hex: p.payload_hex,
        };

        if matches!(p.proto, Protocol::Tcp | Protocol::Udp) {
            let (remote_ip, _, _) = out.remote();
            if let Some((name, source)) = self.domains.lookup(
                p.proto,
                (p.src_ip, p.src_port),
                (p.dst_ip, p.dst_port),
                remote_ip,
            ) {
                out.domain = Some(name);
                out.domain_source = Some(source);
            }
        }
        out
    }
}
