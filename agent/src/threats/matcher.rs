//! Sorted-range matcher for IPv4/IPv6 threat-list lookup.
//!
//! Internally each address is mapped to a `u128` (IPv4 is widened with a
//! tag in the high bits to avoid colliding with IPv6 ranges). Insertion
//! is O(n log n) once at load time; lookup is O(log n).

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListId {
    SpamhausDrop,
    FireholL1,
    TorExit,
    Custom,
}

impl ListId {
    pub fn label(self) -> &'static str {
        match self {
            ListId::SpamhausDrop => "Spamhaus DROP",
            ListId::FireholL1 => "FireHOL Level 1",
            ListId::TorExit => "Tor exit node",
            ListId::Custom => "user list",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Range {
    start: u128,
    end: u128,
    list: ListId,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub list: ListId,
    pub label: &'static str,
}

#[derive(Default)]
pub struct ThreatMatcher {
    /// Sorted by `start`; non-overlapping after `finalize()` collapses them.
    ranges: RwLock<Vec<Range>>,
    /// Raw entry count per list (before merging), for display.
    counts: RwLock<std::collections::HashMap<ListId, usize>>,
}

impl ThreatMatcher {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Add one IPv4/IPv6 host or CIDR.
    pub fn add_cidr(&self, cidr: &str, list: ListId) {
        if let Some((start, end)) = parse_cidr(cidr) {
            self.ranges.write().push(Range { start, end, list });
            *self.counts.write().entry(list).or_default() += 1;
        }
    }

    pub fn count(&self, list: ListId) -> usize {
        self.counts.read().get(&list).copied().unwrap_or(0)
    }

    /// Atomically replace this matcher's content with `fresh`'s, so
    /// holders of the `Arc` (the alert engine) see the new lists.
    pub fn replace_with(&self, fresh: &ThreatMatcher) {
        let ranges = std::mem::take(&mut *fresh.ranges.write());
        let counts = std::mem::take(&mut *fresh.counts.write());
        *self.ranges.write() = ranges;
        *self.counts.write() = counts;
    }

    /// Sort and merge once everything is loaded. Significantly speeds up
    /// later lookups on lists with thousands of entries.
    pub fn finalize(&self) {
        let mut ranges = self.ranges.write();
        ranges.sort_by_key(|r| r.start);
        // Collapse adjacent / overlapping entries. Keep the lowest `list`
        // priority so Spamhaus wins over Firehol etc. (we tag merged
        // entries with the *first* list).
        let mut merged: Vec<Range> = Vec::with_capacity(ranges.len());
        for r in ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                if r.start <= last.end.saturating_add(1) {
                    if r.end > last.end {
                        last.end = r.end;
                    }
                    continue;
                }
            }
            merged.push(r);
        }
        *ranges = merged;
    }

    pub fn len(&self) -> usize {
        self.ranges.read().len()
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<Verdict> {
        let key = ip_to_u128(ip);
        let ranges = self.ranges.read();
        // Binary search for the largest start <= key.
        let pos = match ranges.binary_search_by_key(&key, |r| r.start) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let r = ranges[pos];
        if key <= r.end {
            Some(Verdict {
                list: r.list,
                label: r.list.label(),
            })
        } else {
            None
        }
    }
}

fn ip_to_u128(ip: &IpAddr) -> u128 {
    match ip {
        // Tag IPv4 in the upper bits to keep its space disjoint from IPv6.
        IpAddr::V4(v4) => (1u128 << 96) | (u32::from(*v4) as u128),
        IpAddr::V6(v6) => u128::from(*v6),
    }
}

fn parse_cidr(s: &str) -> Option<(u128, u128)> {
    let s = s.trim();
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        let prefix: u8 = prefix_str.parse().ok()?;
        let ip: IpAddr = ip_str.parse().ok()?;
        cidr_range(ip, prefix)
    } else {
        let ip: IpAddr = s.parse().ok()?;
        let host_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        cidr_range(ip, host_prefix)
    }
}

fn cidr_range(ip: IpAddr, prefix: u8) -> Option<(u128, u128)> {
    let key = ip_to_u128(&ip);
    let (host_bits, max_prefix) = match ip {
        IpAddr::V4(_) => (32u32, 32u8),
        IpAddr::V6(_) => (128u32, 128u8),
    };
    if prefix > max_prefix {
        return None;
    }
    let host_bits = host_bits - prefix as u32;
    // Mask covers the network portion only; the IPv4 tag is preserved.
    let mask = if host_bits == 0 {
        0u128
    } else if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let start = key & !mask;
    let end = key | mask;
    Some((start, end))
}
