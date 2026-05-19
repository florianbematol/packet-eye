//! Common types shared across the capture pipeline.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl Protocol {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEvent {
    pub ts_ms: i64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: Protocol,
    pub len: u32,
    pub tcp_flags: u8,
    pub direction: Direction,
    /// First N bytes of the raw frame, hex-encoded. Capped at 256 bytes
    /// to keep WS payloads small while still letting the UI show a
    /// meaningful Wireshark-style hex dump.
    #[serde(default)]
    pub payload_hex: Option<String>,
}
