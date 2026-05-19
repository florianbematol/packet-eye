//! Best-effort reverse DNS resolution.
//!
//! NOTE: For the MVP this resolver is a no-op (always returns `None`)
//! to avoid pulling a heavy DNS dependency this early. The shape is
//! correct so the rest of the pipeline can already plumb hostnames; we
//! upgrade to `hickory-resolver` (or similar) in a polish iteration.

use std::net::IpAddr;
use std::sync::Arc;

pub struct DnsResolver;

impl DnsResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    /// Returns `Some(hostname)` when the IP has been resolved before, else `None`.
    /// In the MVP implementation, always returns `None`.
    pub fn lookup_or_resolve_async(&self, _ip: &IpAddr) -> Option<String> {
        None
    }
}
