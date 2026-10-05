//! In-memory ring of raw captured frames, exportable as `.pcapng`.
//!
//! Every frame Npcap delivers is copied here (bounded by a byte budget,
//! oldest frames evicted first) so the user can download the recent
//! capture — or a single connection — and open it in Wireshark.

use std::collections::VecDeque;
use std::net::IpAddr;

use parking_lot::Mutex;
use serde::Serialize;

use crate::capture::types::Protocol;
use crate::enrich::domains::FlowKey;

pub struct Frame {
    /// Capture timestamp, microseconds since the Unix epoch.
    pub ts_us: i64,
    pub orig_len: u32,
    pub data: Vec<u8>,
    /// Flow the frame belongs to (`None` for non-IP frames such as ARP).
    pub flow: Option<FlowKey>,
}

struct Inner {
    frames: VecDeque<Frame>,
    bytes: usize,
    linktype: i32,
    dropped: u64,
}

pub struct PcapRing {
    budget: usize,
    inner: Mutex<Inner>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RingInfo {
    pub frames: usize,
    pub bytes: usize,
    pub budget_bytes: usize,
    pub evicted_frames: u64,
    pub oldest_ts_ms: Option<i64>,
    pub newest_ts_ms: Option<i64>,
}

impl PcapRing {
    pub fn new(budget_bytes: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            budget: budget_bytes,
            inner: Mutex::new(Inner {
                frames: VecDeque::new(),
                bytes: 0,
                linktype: 1, // Ethernet
                dropped: 0,
            }),
        })
    }

    pub fn enabled(&self) -> bool {
        self.budget > 0
    }

    /// Start a new capture: drop old frames and remember the link type.
    pub fn reset(&self, linktype: i32) {
        let mut g = self.inner.lock();
        g.frames.clear();
        g.bytes = 0;
        g.dropped = 0;
        g.linktype = linktype;
    }

    pub fn push(
        &self,
        ts_us: i64,
        data: &[u8],
        proto: Protocol,
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
        has_ip: bool,
    ) {
        if self.budget == 0 || data.len() > self.budget {
            return;
        }
        let frame = Frame {
            ts_us,
            orig_len: data.len() as u32,
            data: data.to_vec(),
            flow: has_ip.then(|| FlowKey::new(proto, src, dst)),
        };
        let mut g = self.inner.lock();
        g.bytes += frame.data.len();
        g.frames.push_back(frame);
        while g.bytes > self.budget {
            match g.frames.pop_front() {
                Some(old) => {
                    g.bytes -= old.data.len();
                    g.dropped += 1;
                }
                None => break,
            }
        }
    }

    pub fn info(&self) -> RingInfo {
        let g = self.inner.lock();
        RingInfo {
            frames: g.frames.len(),
            bytes: g.bytes,
            budget_bytes: self.budget,
            evicted_frames: g.dropped,
            oldest_ts_ms: g.frames.front().map(|f| f.ts_us / 1000),
            newest_ts_ms: g.frames.back().map(|f| f.ts_us / 1000),
        }
    }

    /// Serialise the buffered frames (optionally only one flow) as pcapng.
    /// Returns the file bytes and the number of packets written.
    pub fn export(&self, flow: Option<FlowKey>) -> (Vec<u8>, usize) {
        let g = self.inner.lock();
        let selected: Vec<&Frame> = g
            .frames
            .iter()
            .filter(|f| flow.map_or(true, |k| f.flow == Some(k)))
            .collect();
        let size_hint = selected.iter().map(|f| f.data.len() + 32).sum::<usize>() + 128;
        let mut out = Vec::with_capacity(size_hint);
        write_pcapng(g.linktype as u16, selected.iter().copied(), &mut out);
        (out, selected.len())
    }
}

// --------------------------------------------------------------------
// pcapng writer (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng)
// --------------------------------------------------------------------

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

fn push_option(buf: &mut Vec<u8>, code: u16, value: &[u8]) {
    buf.extend_from_slice(&code.to_le_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value);
    buf.extend(std::iter::repeat(0u8).take(pad4(value.len())));
}

fn push_block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let total = (12 + body.len()) as u32;
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
}

pub fn write_pcapng<'a>(linktype: u16, frames: impl Iterator<Item = &'a Frame>, out: &mut Vec<u8>) {
    // Section Header Block.
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes()); // byte-order magic
    shb.extend_from_slice(&1u16.to_le_bytes()); // major
    shb.extend_from_slice(&0u16.to_le_bytes()); // minor
    shb.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
    push_option(&mut shb, 4, b"Packet Eye agent"); // shb_userappl
    push_option(&mut shb, 0, &[]); // opt_endofopt
    push_block(out, 0x0A0D_0D0A, &shb);

    // Interface Description Block.
    let mut idb = Vec::new();
    idb.extend_from_slice(&linktype.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    push_option(&mut idb, 9, &[6]); // if_tsresol: microseconds
    push_option(&mut idb, 0, &[]);
    push_block(out, 0x0000_0001, &idb);

    // Enhanced Packet Blocks.
    for f in frames {
        let ts = f.ts_us.max(0) as u64;
        let mut epb = Vec::with_capacity(20 + f.data.len() + 3);
        epb.extend_from_slice(&0u32.to_le_bytes()); // interface id
        epb.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(ts as u32).to_le_bytes());
        epb.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&f.orig_len.to_le_bytes());
        epb.extend_from_slice(&f.data);
        epb.extend(std::iter::repeat(0u8).take(pad4(f.data.len())));
        push_block(out, 0x0000_0006, &epb);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_at(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }

    /// Walk the block chain and return (type, total_len) for each block.
    fn blocks(b: &[u8]) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        let mut off = 0;
        while off < b.len() {
            let ty = u32_at(b, off);
            let len = u32_at(b, off + 4);
            assert_eq!(len % 4, 0, "block length must be 32-bit aligned");
            assert_eq!(u32_at(b, off + len as usize - 4), len, "trailing length");
            out.push((ty, len));
            off += len as usize;
        }
        out
    }

    #[test]
    fn writes_valid_block_chain() {
        let ring = PcapRing::new(1 << 20);
        let a: (IpAddr, u16) = ("10.0.0.1".parse().unwrap(), 1000);
        let b: (IpAddr, u16) = ("1.1.1.1".parse().unwrap(), 443);
        let c: (IpAddr, u16) = ("8.8.8.8".parse().unwrap(), 53);
        ring.push(1_700_000_000_000_000, &[1, 2, 3], Protocol::Tcp, a, b, true);
        ring.push(1_700_000_000_000_001, &[4; 61], Protocol::Tcp, b, a, true);
        ring.push(1_700_000_000_000_002, &[5; 10], Protocol::Udp, a, c, true);

        let (all, n) = ring.export(None);
        assert_eq!(n, 3);
        let bl = blocks(&all);
        assert_eq!(bl[0].0, 0x0A0D_0D0A);
        assert_eq!(bl[1].0, 1);
        assert_eq!(bl.iter().filter(|(t, _)| *t == 6).count(), 3);

        // Per-flow export keeps both directions of the TCP flow only.
        let (one, n) = ring.export(Some(FlowKey::new(Protocol::Tcp, b, a)));
        assert_eq!(n, 2);
        assert_eq!(blocks(&one).iter().filter(|(t, _)| *t == 6).count(), 2);
    }

    #[test]
    fn evicts_oldest_frames_over_budget() {
        let ring = PcapRing::new(100);
        let a: (IpAddr, u16) = ("10.0.0.1".parse().unwrap(), 1);
        for i in 0..10 {
            ring.push(i, &[0; 30], Protocol::Udp, a, a, true);
        }
        let info = ring.info();
        assert!(info.bytes <= 100);
        assert_eq!(info.frames, 3);
        assert_eq!(info.oldest_ts_ms, Some(0)); // 7µs / 1000
        assert_eq!(info.evicted_frames, 7);
    }

    /// Writes a real Ethernet/IPv4/TCP capture to `$PE_PCAPNG_OUT` so an
    /// external reader (Wireshark, dpkt…) can validate the file format.
    #[test]
    fn dump_for_external_validation() {
        let Ok(path) = std::env::var("PE_PCAPNG_OUT") else { return };
        let ring = PcapRing::new(1 << 20);
        let a: (IpAddr, u16) = ("192.168.1.10".parse().unwrap(), 50000);
        let b: (IpAddr, u16) = ("93.184.216.34".parse().unwrap(), 443);
        for (i, payload) in [&b"hello"[..], &b"world!!"[..], &b"x"[..]].iter().enumerate() {
            let builder = etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
                .ipv4([192, 168, 1, 10], [93, 184, 216, 34], 64)
                .tcp(50000, 443, 1000 + i as u32, 4096);
            let mut frame = Vec::new();
            builder.write(&mut frame, payload).unwrap();
            ring.push(1_700_000_000_000_000 + i as i64 * 1000, &frame, Protocol::Tcp, a, b, true);
        }
        let (bytes, n) = ring.export(None);
        assert_eq!(n, 3);
        std::fs::write(path, bytes).unwrap();
    }
}
