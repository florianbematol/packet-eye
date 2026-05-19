//! Threat-list lookup.
//!
//! At startup we parse a handful of well-known IP block lists (Spamhaus
//! DROP, FireHOL level 1, Tor exit nodes) plus an optional user list,
//! into a single sorted `Vec<Range>` of u128 ranges. Lookups are O(log n)
//! via binary search.

mod loader;
mod matcher;

pub use loader::load_default;
pub use matcher::{ListId, ThreatMatcher, Verdict};
