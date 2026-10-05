//! Locate, load, reload and update the threat-list files.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use super::matcher::{ListId, ThreatMatcher};

/// Upstream lists that can be refreshed from the UI.
pub const UPSTREAM: &[(ListId, &str, &str)] = &[
    (ListId::SpamhausDrop, "spamhaus-drop.txt", "https://www.spamhaus.org/drop/drop.txt"),
    (
        ListId::FireholL1,
        "firehol-level1.netset",
        "https://iplists.firehol.org/files/firehol_level1.netset",
    ),
    (ListId::TorExit, "tor-exit.txt", "https://check.torproject.org/exit-addresses"),
];

const CUSTOM_FILE: &str = "custom.txt";

#[derive(Debug, Serialize)]
pub struct ListInfo {
    pub id: ListId,
    pub label: &'static str,
    pub file: String,
    pub exists: bool,
    pub size_bytes: u64,
    pub modified_iso: Option<String>,
    pub entries: usize,
    pub updatable: bool,
}

#[derive(Debug, Serialize)]
pub struct ThreatsInfo {
    pub total_ranges: usize,
    pub dir: String,
    pub lists: Vec<ListInfo>,
}

/// Find the threat-list directory, creating the per-user one if none of
/// the candidates exists yet (so updates always have somewhere to go).
pub fn resolve_dir() -> PathBuf {
    let candidates = candidate_dirs();
    let has_lists = |d: &Path| {
        UPSTREAM.iter().any(|(_, f, _)| d.join(f).is_file()) || d.join(CUSTOM_FILE).is_file()
    };
    if let Some(d) = candidates.iter().find(|d| has_lists(d)) {
        return d.clone();
    }
    if let Some(d) = candidates.iter().find(|d| d.is_dir()) {
        return d.clone();
    }
    let fallback = candidates.last().cloned().unwrap_or_else(|| PathBuf::from("threat-lists"));
    std::fs::create_dir_all(&fallback).ok();
    fallback
}

/// Load the lists from the resolved directory.
pub fn load_default() -> Arc<ThreatMatcher> {
    let m = ThreatMatcher::new();
    let dir = resolve_dir();
    load_into(&m, &dir);
    m.finalize();
    if m.len() == 0 {
        tracing::warn!(
            "no threat lists in {} (run `npm run fetch-threats` or update them from the UI)",
            dir.display()
        );
    } else {
        tracing::info!("threat lists loaded: {} ranges from {}", m.len(), dir.display());
    }
    m
}

/// Re-read every list from disk and swap it into `target` in place.
pub fn reload(target: &ThreatMatcher) -> usize {
    let fresh = ThreatMatcher::default();
    load_into_ref(&fresh, &resolve_dir());
    fresh.finalize();
    target.replace_with(&fresh);
    target.len()
}

pub fn info(m: &ThreatMatcher) -> ThreatsInfo {
    let dir = resolve_dir();
    let mut lists: Vec<ListInfo> = UPSTREAM
        .iter()
        .map(|(id, file, _)| file_info(&dir, *id, file, m, true))
        .collect();
    lists.push(file_info(&dir, ListId::Custom, CUSTOM_FILE, m, false));
    ThreatsInfo {
        total_ranges: m.len(),
        dir: dir.display().to_string(),
        lists,
    }
}

fn file_info(dir: &Path, id: ListId, file: &str, m: &ThreatMatcher, updatable: bool) -> ListInfo {
    let meta = std::fs::metadata(dir.join(file)).ok();
    ListInfo {
        id,
        label: id.label(),
        file: file.to_string(),
        exists: meta.is_some(),
        size_bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
        modified_iso: meta.and_then(|m| m.modified().ok()).and_then(|t| {
            let dt: time::OffsetDateTime = t.into();
            dt.format(&time::format_description::well_known::Rfc3339).ok()
        }),
        entries: m.count(id),
        updatable,
    }
}

#[derive(Debug, Serialize)]
pub struct UpdateResult {
    pub file: String,
    pub ok: bool,
    pub error: Option<String>,
    pub size_bytes: u64,
}

/// Download every upstream list into the resolved directory (atomic
/// rename per file). A failing list keeps its previous version.
pub async fn download_all() -> Vec<UpdateResult> {
    let dir = resolve_dir();
    std::fs::create_dir_all(&dir).ok();
    let client = match reqwest::Client::builder()
        .user_agent("packet-eye-agent/0.1")
        .timeout(Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return UPSTREAM
                .iter()
                .map(|(_, f, _)| UpdateResult {
                    file: f.to_string(),
                    ok: false,
                    error: Some(e.to_string()),
                    size_bytes: 0,
                })
                .collect()
        }
    };
    let mut results = Vec::new();
    for (_, file, url) in UPSTREAM {
        let res: Result<u64, String> = async {
            let resp = client.get(*url).send().await.map_err(|e| e.to_string())?;
            if !resp.status().is_success() {
                return Err(format!("HTTP {}", resp.status()));
            }
            let body = resp.bytes().await.map_err(|e| e.to_string())?;
            if body.len() < 1024 {
                return Err(format!("download too small ({} bytes)", body.len()));
            }
            let dest = dir.join(file);
            let tmp = dir.join(format!("{file}.download"));
            std::fs::write(&tmp, &body).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
            Ok(body.len() as u64)
        }
        .await;
        results.push(match res {
            Ok(size) => UpdateResult { file: file.to_string(), ok: true, error: None, size_bytes: size },
            Err(e) => UpdateResult { file: file.to_string(), ok: false, error: Some(e), size_bytes: 0 },
        });
    }
    results
}

fn candidate_dirs() -> Vec<PathBuf> {
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
    load_into_ref(m, dir);
}

fn load_into_ref(m: &ThreatMatcher, dir: &Path) {
    load_simple(m, &dir.join("spamhaus-drop.txt"), ListId::SpamhausDrop);
    load_simple(m, &dir.join("firehol-level1.netset"), ListId::FireholL1);
    load_tor(m, &dir.join("tor-exit.txt"));
    load_simple(m, &dir.join(CUSTOM_FILE), ListId::Custom);
}

/// Parse a list where each non-comment line starts with an IP or CIDR.
fn load_simple(m: &ThreatMatcher, path: &Path, list: ListId) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // First token is the IP or CIDR; ignore the rest (comments).
        let token = line
            .split(|c: char| c.is_whitespace() || c == ';')
            .next()
            .unwrap_or("")
            .trim();
        if !token.is_empty() {
            m.add_cidr(token, list);
        }
    }
}

/// Tor exit-addresses format:
///   ExitNode <fp>
///   Published <ts>
///   LastStatus <ts>
///   ExitAddress <ip> <ts>
fn load_tor(m: &ThreatMatcher, path: &Path) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("ExitAddress ") {
            if let Some(ip) = rest.split_whitespace().next() {
                m.add_cidr(ip, ListId::TorExit);
            }
        }
    }
}
