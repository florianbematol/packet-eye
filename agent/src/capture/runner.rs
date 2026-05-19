//! The capture loop. Pure capture/parse — does NOT know about Tauri or
//! WebSockets. Each parsed packet is handed to a user-supplied callback
//! that's free to do whatever (enrich, batch, broadcast).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use anyhow::{anyhow, Result};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device, Linktype};

use super::bpf::CaptureFilter;
use super::types::{Direction, PacketEvent, Protocol};

/// Type alias for the per-packet callback.
pub type PacketCallback = Arc<dyn Fn(PacketEvent) + Send + Sync + 'static>;

/// Handle to a running capture. Drop or call [`Runner::stop`] to terminate.
pub struct Runner {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Runner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runner")
            .field("running", &!self.stop.load(Ordering::Relaxed))
            .finish()
    }
}

impl Runner {
    pub fn spawn(
        device_name: &str,
        filter: &CaptureFilter,
        on_packet: PacketCallback,
    ) -> Result<Self> {
        let devices = Device::list()?;
        let device = devices
            .into_iter()
            .find(|d| d.name == device_name)
            .ok_or_else(|| anyhow!("device not found: {device_name}"))?;

        tracing::info!(
            "opening capture on {} ({:?})",
            device.name,
            device.desc.as_deref().unwrap_or("?")
        );

        let mut cap: Capture<pcap::Active> = Capture::from_device(device)?
            .promisc(true)
            .immediate_mode(true)
            // Capture the full Ethernet MTU so we keep the layer-7 payload
            // available for the hex viewer / future deep-packet inspection.
            // 65535 means "no truncation" in libpcap parlance.
            .snaplen(65535)
            .buffer_size(8 * 1024 * 1024)
            .timeout(50)
            .open()?;

        let bpf = filter.to_bpf();
        if !bpf.is_empty() {
            tracing::info!("BPF filter: {bpf}");
            cap.filter(&bpf, true)?;
        }

        let linktype = cap.get_datalink();
        tracing::info!("link type: {:?}", linktype);

        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = stop.clone();
        let join = thread::Builder::new()
            .name("packet-eye-capture".into())
            .spawn(move || {
                run_loop(cap, linktype, stop_t, on_packet);
            })?;

        Ok(Self {
            stop,
            join: Some(join),
        })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_loop(
    mut cap: Capture<pcap::Active>,
    linktype: Linktype,
    stop: Arc<AtomicBool>,
    on_packet: PacketCallback,
) {
    let mut errors = 0u64;
    let mut total = 0u64;
    while !stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                total += 1;
                let ts_ms = (packet.header.ts.tv_sec as i64) * 1000
                    + (packet.header.ts.tv_usec as i64) / 1000;
                if let Some(evt) = parse_packet(linktype, packet.data, ts_ms) {
                    on_packet(evt);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                errors += 1;
                if errors < 10 {
                    tracing::warn!("pcap error: {e}");
                } else if errors == 10 {
                    tracing::warn!("pcap errors: muting further messages");
                }
            }
        }
    }
    tracing::info!("capture loop exited (total={total} errors={errors})");
}

fn parse_packet(linktype: Linktype, data: &[u8], ts_ms: i64) -> Option<PacketEvent> {
    // Always try to slice the frame so we can extract whatever layers
    // are present. Failing to parse just means we'll surface the packet
    // with `proto: Other` and zeroed addresses — the raw payload still
    // makes it through.
    let sliced_opt = match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok(),
        Linktype::NULL | Linktype::LOOP => {
            if data.len() < 4 {
                None
            } else {
                SlicedPacket::from_ip(&data[4..]).ok()
            }
        }
        Linktype::RAW => SlicedPacket::from_ip(data).ok(),
        _ => SlicedPacket::from_ethernet(data)
            .or_else(|_| SlicedPacket::from_ip(data))
            .ok(),
    };

    let zero4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let (src_ip, dst_ip) = sliced_opt
        .as_ref()
        .and_then(|s| s.net.as_ref())
        .map(|n| match n {
            NetSlice::Ipv4(v4) => {
                let h = v4.header();
                (
                    IpAddr::V4(Ipv4Addr::from(h.source())),
                    IpAddr::V4(Ipv4Addr::from(h.destination())),
                )
            }
            NetSlice::Ipv6(v6) => {
                let h = v6.header();
                (
                    IpAddr::V6(Ipv6Addr::from(h.source_addr().octets())),
                    IpAddr::V6(Ipv6Addr::from(h.destination_addr().octets())),
                )
            }
        })
        .unwrap_or((zero4, zero4));

    let (proto, src_port, dst_port, tcp_flags) = sliced_opt
        .as_ref()
        .and_then(|s| s.transport.as_ref())
        .map(|t| match t {
            TransportSlice::Tcp(tcp) => {
                let mut flags = 0u8;
                if tcp.fin() { flags |= 0b0000_0001; }
                if tcp.syn() { flags |= 0b0000_0010; }
                if tcp.rst() { flags |= 0b0000_0100; }
                if tcp.psh() { flags |= 0b0000_1000; }
                if tcp.ack() { flags |= 0b0001_0000; }
                if tcp.urg() { flags |= 0b0010_0000; }
                (Protocol::Tcp, tcp.source_port(), tcp.destination_port(), flags)
            }
            TransportSlice::Udp(udp) => (
                Protocol::Udp,
                udp.source_port(),
                udp.destination_port(),
                0,
            ),
            TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
                (Protocol::Icmp, 0, 0, 0)
            }
        })
        .unwrap_or((Protocol::Other, 0, 0, 0));

    // Hex-encode the first PAYLOAD_HEX_CAP bytes of the raw frame so the
    // UI's "raw" panel can render a Wireshark-style dump.
    const PAYLOAD_HEX_CAP: usize = 256;
    let take = data.len().min(PAYLOAD_HEX_CAP);
    let payload_hex = if take > 0 {
        Some(encode_hex(&data[..take]))
    } else {
        None
    };

    Some(PacketEvent {
        ts_ms,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        len: data.len() as u32,
        tcp_flags,
        direction: Direction::Unknown,
        payload_hex,
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
