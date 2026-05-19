//! Parse threat list files into the matcher.

use std::path::Path;
use std::sync::Arc;

use super::matcher::{ListId, ThreatMatcher};

/// Resolve where the bundled threat lists live, then load whatever is found.
pub fn load_default() -> Arc<ThreatMatcher> {
    let m = ThreatMatcher::new();

    let candidates = candidate_dirs();
    for dir in &candidates {
        if !dir.exists() {
            continue;
        }
        load_into(&m, dir);
        return finalize(m);
    }

    tracing::warn!(
        "no threat-list directory found (checked {} paths)",
        candidates.len()
    );
    finalize(m)
}

fn finalize(m: Arc<ThreatMatcher>) -> Arc<ThreatMatcher> {
    m.finalize();
    tracing::info!("threat lists loaded: {} ranges", m.len());
    m
}

fn candidate_dirs() -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        v.push(cwd.join("resources").join("threat-lists"));
        // Handy when running `cargo run` from the workspace root.
        v.push(cwd.join("agent").join("resources").join("threat-lists"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            v.push(parent.join("resources").join("threat-lists"));
            if let Some(grand) = parent.parent().and_then(|p| p.parent()) {
                v.push(grand.join("resources").join("threat-lists"));
            }
        }
    }
    if let Some(dirs) = directories::ProjectDirs::from("dev", "packet-eye", "packet-eye") {
        v.push(dirs.data_dir().join("threat-lists"));
    }
    v
}

fn load_into(m: &Arc<ThreatMatcher>, dir: &Path) {
    load_simple(m, &dir.join("spamhaus-drop.txt"), ListId::SpamhausDrop);
    load_simple(m, &dir.join("firehol-level1.netset"), ListId::FireholL1);
    load_tor(m, &dir.join("tor-exit.txt"));
    load_simple(m, &dir.join("custom.txt"), ListId::Custom);
}

/// Parse a list where each non-comment line starts with an IP or CIDR.
fn load_simple(m: &Arc<ThreatMatcher>, path: &Path, list: ListId) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut count = 0;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // First token is the IP or CIDR; ignore the rest (comments).
        let token = line
            .split(|c: char| c.is_whitespace() || c == ';')
            .next()
            .unwrap_or("")
            .trim();
        if token.is_empty() {
            continue;
        }
        m.add_cidr(token, list);
        count += 1;
    }
    if count > 0 {
        tracing::debug!("threats[{:?}]: loaded {count} entries from {}", list, path.display());
    }
}

/// Tor exit-addresses format:
///   ExitNode <fp>
///   Published <ts>
///   LastStatus <ts>
///   ExitAddress <ip> <ts>
fn load_tor(m: &Arc<ThreatMatcher>, path: &Path) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut count = 0;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("ExitAddress ") {
            if let Some(ip) = rest.split_whitespace().next() {
                m.add_cidr(ip, ListId::TorExit);
                count += 1;
            }
        }
    }
    if count > 0 {
        tracing::debug!("threats[TorExit]: loaded {count} entries");
    }
}
