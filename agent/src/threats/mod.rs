//! Threat-list lookup.
//!
//! At startup we parse a handful of well-known IP block lists (Spamhaus
//! DROP, FireHOL level 1, Tor exit nodes) plus an optional user list,
//! into a single sorted `Vec<Range>` of u128 ranges. Lookups are O(log n)
//! via binary search. Lists can be re-downloaded and hot-reloaded.

mod loader;
mod matcher;

pub use loader::{download_all, info, load_default, reload, ThreatsInfo, UpdateResult};
pub use matcher::{ListId, ThreatMatcher, Verdict};
