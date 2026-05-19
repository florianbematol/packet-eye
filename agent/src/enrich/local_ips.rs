//! Determines which IP addresses are local (this machine), so we can
//! classify each packet as inbound / outbound / unknown.
//!
//! The set is rebuilt periodically (via `refresh()`) because users may
//! plug/unplug VPNs or interfaces. Lookups themselves are O(1).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::capture::types::Direction;

pub struct LocalIps {
    set: RwLock<HashSet<IpAddr>>,
}

impl LocalIps {
    pub fn new() -> Arc<Self> {
        let me = Arc::new(Self {
            set: RwLock::new(HashSet::new()),
        });
        me.refresh();
        me
    }

    /// Re-enumerate local interfaces. Cheap to call.
    pub fn refresh(&self) {
        let mut next = HashSet::new();
        for d in pcap::Device::list().unwrap_or_default() {
            for a in d.addresses {
                next.insert(a.addr);
            }
        }
        // Always include the obvious loopback addresses.
        next.insert("127.0.0.1".parse().unwrap());
        next.insert("::1".parse().unwrap());
        let count = next.len();
        *self.set.write() = next;
        tracing::debug!("local IP set refreshed: {count} entries");
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.set.read().contains(ip)
    }

    /// Heuristic: src is ours -> outbound, dst is ours -> inbound, else unknown.
    pub fn classify(&self, src: &IpAddr, dst: &IpAddr) -> Direction {
        let set = self.set.read();
        let src_local = set.contains(src);
        let dst_local = set.contains(dst);
        match (src_local, dst_local) {
            (true, false) => Direction::Outbound,
            (false, true) => Direction::Inbound,
            _ => Direction::Unknown,
        }
    }
}
