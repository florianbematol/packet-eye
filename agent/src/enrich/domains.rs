//! Passive domain discovery.
//!
//! Instead of reverse DNS (which returns CDN junk like
//! `a23-45-67-89.deploy.static.akamaitechnologies.com`), we learn the
//! name the *application* actually asked for, straight from the traffic:
//!
//! * **TLS ClientHello SNI** — the hostname a client wants to reach over
//!   HTTPS. Sent in clear text in the first TLS record. Modern
//!   ClientHellos (post-quantum key shares) often exceed one TCP segment,
//!   so we reassemble the first record per flow (bounded, best effort).
//! * **HTTP `Host:` header** — plain-text HTTP requests.
//! * **DNS responses** — A / AAAA answers map an IP back to the name that
//!   was queried (the question name, not the CNAME target, so you see
//!   `www.netflix.com` rather than `e1234.akamai.net`).
//!
//! Learned names are stored per flow (most precise: one SNI per TLS
//! connection) and per IP (fallback for flows we didn't see start).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::capture::types::Protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainSource {
    Dns,
    Http,
    Sni,
}

impl DomainSource {
    fn rank(self) -> u8 {
        match self {
            DomainSource::Dns => 0,
            DomainSource::Http => 1,
            DomainSource::Sni => 2,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    source: DomainSource,
    at: Instant,
}

/// Direction-independent flow key (proto + the two endpoints, sorted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    proto: u8,
    a: (IpAddr, u16),
    b: (IpAddr, u16),
}

impl FlowKey {
    pub fn new(proto: Protocol, src: (IpAddr, u16), dst: (IpAddr, u16)) -> Self {
        let p = match proto {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmp => 1,
            Protocol::Other => 0,
        };
        let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
        Self { proto: p, a, b }
    }
}

const MAX_HELLO: usize = 16 * 1024;
const PENDING_TTL: Duration = Duration::from_secs(5);
/// A weaker source (DNS) may overwrite a stronger one after this delay.
const STALE_AFTER: Duration = Duration::from_secs(600);

struct Pending {
    buf: Vec<u8>,
    dst_ip: IpAddr,
    started: Instant,
}

pub struct DomainSniffer {
    by_flow: Mutex<lru::LruCache<FlowKey, Entry>>,
    by_ip: Mutex<lru::LruCache<IpAddr, Entry>>,
    pending: Mutex<HashMap<FlowKey, Pending>>,
}

impl Default for DomainSniffer {
    fn default() -> Self {
        Self {
            by_flow: Mutex::new(lru::LruCache::new(NonZeroUsize::new(32_768).unwrap())),
            by_ip: Mutex::new(lru::LruCache::new(NonZeroUsize::new(32_768).unwrap())),
            pending: Mutex::new(HashMap::new()),
        }
    }
}

impl DomainSniffer {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Inspect one packet's L4 payload. Cheap for packets that carry
    /// nothing interesting (a couple of byte comparisons).
    pub fn observe(
        &self,
        proto: Protocol,
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
        payload: &[u8],
    ) {
        if payload.is_empty() {
            return;
        }
        match proto {
            Protocol::Udp if src.1 == 53 => {
                for (ip, name) in parse_dns_response(payload) {
                    self.learn_ip(ip, name, DomainSource::Dns);
                }
            }
            Protocol::Tcp => self.observe_tcp(src, dst, payload),
            _ => {}
        }
    }

    fn observe_tcp(&self, src: (IpAddr, u16), dst: (IpAddr, u16), payload: &[u8]) {
        let key = FlowKey::new(Protocol::Tcp, src, dst);

        // Continuation of a ClientHello we started buffering.
        {
            let mut pending = self.pending.lock();
            if let Some(p) = pending.get_mut(&key) {
                if p.dst_ip == dst.0 {
                    p.buf.extend_from_slice(payload);
                    match parse_client_hello_sni(&p.buf) {
                        HelloParse::Sni(name) => {
                            let dst_ip = p.dst_ip;
                            pending.remove(&key);
                            drop(pending);
                            self.learn_flow(key, dst_ip, name, DomainSource::Sni);
                        }
                        HelloParse::NeedMore if p.buf.len() < MAX_HELLO => {}
                        _ => {
                            pending.remove(&key);
                        }
                    }
                }
                return;
            }
        }

        if payload.len() >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01 {
            match parse_client_hello_sni(payload) {
                HelloParse::Sni(name) => self.learn_flow(key, dst.0, name, DomainSource::Sni),
                HelloParse::NeedMore => {
                    let mut pending = self.pending.lock();
                    // Opportunistic GC so abandoned handshakes don't pile up.
                    if pending.len() > 256 {
                        pending.retain(|_, p| p.started.elapsed() < PENDING_TTL);
                    }
                    pending.insert(
                        key,
                        Pending {
                            buf: payload.to_vec(),
                            dst_ip: dst.0,
                            started: Instant::now(),
                        },
                    );
                }
                HelloParse::None => {}
            }
        } else if let Some(host) = parse_http_host(payload) {
            self.learn_flow(key, dst.0, host, DomainSource::Http);
        }
    }

    fn learn_flow(&self, key: FlowKey, server_ip: IpAddr, name: String, source: DomainSource) {
        self.by_flow.lock().put(
            key,
            Entry {
                name: name.clone(),
                source,
                at: Instant::now(),
            },
        );
        self.learn_ip(server_ip, name, source);
    }

    fn learn_ip(&self, ip: IpAddr, name: String, source: DomainSource) {
        let mut map = self.by_ip.lock();
        let replace = match map.peek(&ip) {
            Some(old) => source.rank() >= old.source.rank() || old.at.elapsed() > STALE_AFTER,
            None => true,
        };
        if replace {
            map.put(
                ip,
                Entry {
                    name,
                    source,
                    at: Instant::now(),
                },
            );
        }
    }

    /// Best known name for the remote side of a flow.
    pub fn lookup(
        &self,
        proto: Protocol,
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
        remote_ip: IpAddr,
    ) -> Option<(String, DomainSource)> {
        let key = FlowKey::new(proto, src, dst);
        if let Some(e) = self.by_flow.lock().get(&key) {
            return Some((e.name.clone(), e.source));
        }
        self.by_ip
            .lock()
            .get(&remote_ip)
            .map(|e| (e.name.clone(), e.source))
    }
}

// --------------------------------------------------------------------
// TLS ClientHello
// --------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum HelloParse {
    Sni(String),
    NeedMore,
    None,
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|s| ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }
}

/// Parse the SNI out of a TLS record stream that starts with a
/// ClientHello. Returns `NeedMore` when the hello is truncated.
fn parse_client_hello_sni(data: &[u8]) -> HelloParse {
    // Gather the handshake message from (possibly several) records.
    let mut hs: Vec<u8> = Vec::new();
    let mut r = Reader::new(data);
    let mut hs_len: Option<usize> = None;
    loop {
        if let Some(need) = hs_len {
            if hs.len() >= need + 4 {
                break;
            }
        }
        let header = match r.take(5) {
            Some(h) => h,
            None => return HelloParse::NeedMore,
        };
        if header[0] != 0x16 || header[1] != 0x03 {
            return HelloParse::None;
        }
        let rec_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let avail = r.b.len() - r.pos;
        let chunk = &r.b[r.pos..r.pos + rec_len.min(avail)];
        hs.extend_from_slice(chunk);
        if hs_len.is_none() && hs.len() >= 4 {
            if hs[0] != 0x01 {
                return HelloParse::None;
            }
            hs_len = Some(((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize);
        }
        if rec_len > avail {
            break; // record truncated: parse what we have
        }
        r.pos += rec_len;
        if r.pos >= r.b.len() {
            break;
        }
    }

    let mut h = Reader::new(&hs);
    if h.u8() != Some(0x01) {
        return if hs.len() < 4 { HelloParse::NeedMore } else { HelloParse::None };
    }
    let body_len = match h.u24() {
        Some(l) => l,
        None => return HelloParse::NeedMore,
    };
    let complete = hs.len() >= body_len + 4;

    let mut walk = || -> Option<HelloParse> {
        h.take(2)?; // legacy_version
        h.take(32)?; // random
        let sid = h.u8()? as usize;
        h.take(sid)?;
        let cs = h.u16()? as usize;
        h.take(cs)?;
        let comp = h.u8()? as usize;
        h.take(comp)?;
        let ext_total = h.u16()? as usize;
        let ext_end = h.pos + ext_total;
        while h.pos + 4 <= ext_end {
            let ty = h.u16()?;
            let len = h.u16()? as usize;
            let body = h.take(len)?;
            if ty == 0x0000 {
                let mut e = Reader::new(body);
                let list_len = e.u16()? as usize;
                let list_end = e.pos + list_len;
                while e.pos + 3 <= list_end {
                    let name_type = e.u8()?;
                    let nlen = e.u16()? as usize;
                    let name = e.take(nlen)?;
                    if name_type == 0 {
                        let s = std::str::from_utf8(name).ok()?;
                        return Some(match sanitize_hostname(s) {
                            Some(v) => HelloParse::Sni(v),
                            None => HelloParse::None,
                        });
                    }
                }
                return Some(HelloParse::None);
            }
        }
        Some(HelloParse::None)
    };

    match walk() {
        Some(res) => res,
        // Ran out of bytes before finding the SNI extension.
        None if !complete => HelloParse::NeedMore,
        None => HelloParse::None,
    }
}

// --------------------------------------------------------------------
// HTTP Host header
// --------------------------------------------------------------------

fn parse_http_host(payload: &[u8]) -> Option<String> {
    const METHODS: &[&[u8]] = &[
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    ];
    if !METHODS.iter().any(|m| payload.starts_with(m)) {
        return None;
    }
    let head = &payload[..payload.len().min(4096)];
    let text = std::str::from_utf8(head).ok().or_else(|| {
        // Cut at the last valid UTF-8 boundary.
        let valid = std::str::from_utf8(head).err()?.valid_up_to();
        std::str::from_utf8(&head[..valid]).ok()
    })?;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let v = v.trim();
                // Strip port, keep bracketed IPv6 intact.
                let host = if v.starts_with('[') {
                    v.split(']').next().map(|h| format!("{h}]")).unwrap_or_default()
                } else {
                    v.split(':').next().unwrap_or("").to_string()
                };
                return sanitize_hostname(&host);
            }
        }
    }
    None
}

// --------------------------------------------------------------------
// DNS responses
// --------------------------------------------------------------------

fn parse_dns_response(msg: &[u8]) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    let mut r = Reader::new(msg);
    let mut parse = || -> Option<()> {
        r.take(2)?; // id
        let flags = r.u16()?;
        if flags & 0x8000 == 0 || flags & 0x000f != 0 {
            return None; // not a response, or an error rcode
        }
        let qd = r.u16()?;
        let an = r.u16()?;
        r.take(4)?; // ns + ar counts
        let mut qname: Option<String> = None;
        for _ in 0..qd {
            let (name, next) = read_name(msg, r.pos)?;
            r.pos = next;
            r.take(4)?; // qtype + qclass
            if qname.is_none() {
                qname = Some(name);
            }
        }
        let qname = sanitize_hostname(&qname?)?;
        for _ in 0..an {
            let (_, next) = read_name(msg, r.pos)?;
            r.pos = next;
            let ty = r.u16()?;
            r.take(6)?; // class + ttl
            let rdlen = r.u16()? as usize;
            let rdata = r.take(rdlen)?;
            match (ty, rdlen) {
                (1, 4) => out.push((
                    IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                    qname.clone(),
                )),
                (28, 16) => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(rdata);
                    out.push((IpAddr::V6(Ipv6Addr::from(o)), qname.clone()));
                }
                _ => {}
            }
        }
        Some(())
    };
    let _ = parse();
    out
}

/// Decode a (possibly compressed) DNS name starting at `pos`. Returns the
/// name and the offset right after it in the *original* position.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut end = pos;
    let mut hops = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            if !jumped {
                end = pos + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            if !jumped {
                end = pos + 2;
            }
            jumped = true;
            pos = ptr;
            hops += 1;
            if hops > 16 {
                return None;
            }
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), end))
}

/// Keep only plausible hostnames (letters, digits, `-`, `.`, `_`).
fn sanitize_hostname(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_') {
        Some(s)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS 1.2-style ClientHello carrying `sni`, with
    /// `pad` bytes of filler extension placed *before* the SNI.
    fn client_hello(sni: &str, pad: usize) -> Vec<u8> {
        let mut ext = Vec::new();
        if pad > 0 {
            ext.extend_from_slice(&0x0015u16.to_be_bytes()); // padding ext
            ext.extend_from_slice(&(pad as u16).to_be_bytes());
            ext.extend(std::iter::repeat(0u8).take(pad));
        }
        let name = sni.as_bytes();
        let mut sni_body = Vec::new();
        sni_body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_body.push(0);
        sni_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(name);
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_body);

        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sni_single_segment() {
        let hello = client_hello("www.Example.com", 0);
        assert_eq!(parse_client_hello_sni(&hello), HelloParse::Sni("www.example.com".into()));
    }

    #[test]
    fn sni_split_across_segments_is_reassembled() {
        let s = DomainSniffer::default();
        let hello = client_hello("xboxlive.com", 2000);
        let client: (IpAddr, u16) = ("192.168.1.10".parse().unwrap(), 50000);
        let server: (IpAddr, u16) = ("23.1.2.3".parse().unwrap(), 443);
        let (a, b) = hello.split_at(1400);
        assert_eq!(parse_client_hello_sni(a), HelloParse::NeedMore);
        s.observe(Protocol::Tcp, client, server, a);
        assert!(s.lookup(Protocol::Tcp, client, server, server.0).is_none());
        s.observe(Protocol::Tcp, client, server, b);
        let got = s.lookup(Protocol::Tcp, server, client, server.0);
        assert_eq!(got, Some(("xboxlive.com".into(), DomainSource::Sni)));
    }

    #[test]
    fn http_host_header() {
        let req = b"GET /index.html HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.org:8080\r\n\r\n";
        assert_eq!(parse_http_host(req), Some("example.org".into()));
        assert_eq!(parse_http_host(b"\x16\x03\x01garbage"), None);
    }

    #[test]
    fn dns_answers_map_to_question_name() {
        // Response for www.netflix.com: CNAME then A record (compressed names).
        let mut m = vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0,
        ];
        for label in ["www", "netflix", "com"] {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        // CNAME answer -> "edge.example" (uncompressed target)
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60]);
        let target = [4u8, b'e', b'd', b'g', b'e', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];
        m.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let target_off = m.len();
        m.extend_from_slice(&target);
        // A answer for the CNAME target (pointer to it).
        m.extend_from_slice(&[0xc0, target_off as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 52, 1, 2, 3]);
        let got = parse_dns_response(&m);
        assert_eq!(got, vec![("52.1.2.3".parse().unwrap(), "www.netflix.com".into())]);
    }

    /// Parses a real ClientHello captured from a TLS stack, given through
    /// `$PE_CLIENT_HELLO` (raw record bytes) and `$PE_CLIENT_HELLO_SNI`.
    /// Also checks reassembly when the hello is split at every 500 bytes.
    #[test]
    fn real_client_hello_from_env() {
        let (Ok(path), Ok(expected)) =
            (std::env::var("PE_CLIENT_HELLO"), std::env::var("PE_CLIENT_HELLO_SNI"))
        else {
            return;
        };
        let hello = std::fs::read(path).unwrap();
        assert_eq!(parse_client_hello_sni(&hello), HelloParse::Sni(expected.clone()));

        let s = DomainSniffer::default();
        let c: (IpAddr, u16) = ("10.0.0.2".parse().unwrap(), 51000);
        let srv: (IpAddr, u16) = ("1.2.3.4".parse().unwrap(), 443);
        for chunk in hello.chunks(500) {
            s.observe(Protocol::Tcp, c, srv, chunk);
        }
        assert_eq!(s.lookup(Protocol::Tcp, c, srv, srv.0), Some((expected, DomainSource::Sni)));
    }
    #[test]
    fn weaker_source_does_not_override_sni() {
        let s = DomainSniffer::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        s.learn_ip(ip, "real.example".into(), DomainSource::Sni);
        s.learn_ip(ip, "other.example".into(), DomainSource::Dns);
        let peer: (IpAddr, u16) = ("10.0.0.1".parse().unwrap(), 1);
        assert_eq!(
            s.lookup(Protocol::Tcp, peer, (ip, 443), ip),
            Some(("real.example".into(), DomainSource::Sni))
        );
    }
}
