//! GeoIP enrichment using MaxMind GeoLite2 databases (City + ASN)
//! mirrored at https://github.com/P3TERX/GeoLite.mmdb.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use maxminddb::{geoip2, Reader};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::Args;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoLookup {
    pub country: Option<String>,
    pub country_iso: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}

impl GeoLookup {
    pub fn is_empty(&self) -> bool {
        self.country.is_none()
            && self.city.is_none()
            && self.lat.is_none()
            && self.asn.is_none()
    }
}

type LruCache = lru::LruCache<IpAddr, GeoLookup>;

pub struct GeoIpResolver {
    city: RwLock<Option<Reader<Vec<u8>>>>,
    asn: RwLock<Option<Reader<Vec<u8>>>>,
    cache: Mutex<LruCache>,
}

impl GeoIpResolver {
    pub fn empty() -> Self {
        Self {
            city: RwLock::new(None),
            asn: RwLock::new(None),
            cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(8192).unwrap(),
            )),
        }
    }

    pub fn open(city_path: &Path, asn_path: &Path) -> Result<Self> {
        let r = Self::empty();
        r.reload(city_path, asn_path)?;
        Ok(r)
    }

    pub fn reload(&self, city_path: &Path, asn_path: &Path) -> Result<()> {
        let city = open_reader(city_path).context("opening GeoLite2-City.mmdb")?;
        let asn = open_reader(asn_path).context("opening GeoLite2-ASN.mmdb")?;
        *self.city.write() = Some(city);
        *self.asn.write() = Some(asn);
        self.cache.lock().clear();
        tracing::info!(
            "GeoIP databases loaded: city={} asn={}",
            city_path.display(),
            asn_path.display()
        );
        Ok(())
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<GeoLookup> {
        if !is_public(ip) {
            return None;
        }

        if let Some(hit) = self.cache.lock().get(ip).cloned() {
            return if hit.is_empty() { None } else { Some(hit) };
        }

        let mut out = GeoLookup::default();

        if let Some(city_reader) = self.city.read().as_ref() {
            if let Ok(c) = city_reader.lookup::<geoip2::City>(*ip) {
                if let Some(country) = c.country {
                    out.country_iso = country.iso_code.map(|s| s.to_string());
                    out.country = country
                        .names
                        .as_ref()
                        .and_then(|n| n.get("en").or_else(|| n.values().next()))
                        .map(|s| s.to_string());
                }
                if let Some(city) = c.city {
                    out.city = city
                        .names
                        .as_ref()
                        .and_then(|n| n.get("en").or_else(|| n.values().next()))
                        .map(|s| s.to_string());
                }
                if let Some(loc) = c.location {
                    out.lat = loc.latitude;
                    out.lon = loc.longitude;
                }
            }
        }

        if let Some(asn_reader) = self.asn.read().as_ref() {
            if let Ok(a) = asn_reader.lookup::<geoip2::Asn>(*ip) {
                out.asn = a.autonomous_system_number;
                out.asn_org = a
                    .autonomous_system_organization
                    .map(|s| s.to_string());
            }
        }

        self.cache.lock().put(*ip, out.clone());
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

fn open_reader(path: &Path) -> Result<Reader<Vec<u8>>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading mmdb at {}", path.display()))?;
    Reader::from_source(bytes)
        .map_err(|e| anyhow!("invalid mmdb at {}: {e}", path.display()))
}

/// Resolve where a given mmdb lives. Lookup order:
///   1. CLI override (if provided).
///   2. `<cwd>/resources/<filename>`.
///   3. `<cwd>/agent/resources/<filename>` (handy when running `cargo run`
///      from the workspace root).
///   4. `<exe-dir>/resources/<filename>`.
///   5. `<exe-dir>/../../resources/<filename>` (cargo target/debug layout).
///   6. `%APPDATA%/packet-eye/packet-eye/data/geoip/<filename>` (set by
///      runtime updater).
fn resolve_path(filename: &str, cli_override: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = cli_override {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let candidates = [
            cwd.join("resources").join(filename),
            cwd.join("agent").join("resources").join(filename),
        ];
        for p in candidates {
            if p.is_file() {
                return Some(p);
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        // <exe-dir>/resources
        if let Some(parent) = exe.parent() {
            let p = parent.join("resources").join(filename);
            if p.is_file() {
                return Some(p);
            }
            // <exe-dir>/../../resources  (e.g. agent/target/debug/.. /.. /resources)
            if let Some(grand) = parent.parent().and_then(|p| p.parent()) {
                let p = grand.join("resources").join(filename);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    if let Some(dirs) = directories::ProjectDirs::from("dev", "packet-eye", "packet-eye") {
        let p = dirs.data_dir().join("geoip").join(filename);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

pub fn open_with_args(args: &Args) -> Arc<GeoIpResolver> {
    let city = resolve_path("GeoLite2-City.mmdb", args.city_db.as_deref());
    let asn = resolve_path("GeoLite2-ASN.mmdb", args.asn_db.as_deref());
    match (city, asn) {
        (Some(c), Some(a)) => match GeoIpResolver::open(&c, &a) {
            Ok(r) => Arc::new(r),
            Err(e) => {
                tracing::error!("GeoIP load failed: {e:#}; running with empty resolver");
                Arc::new(GeoIpResolver::empty())
            }
        },
        (c, a) => {
            if c.is_none() {
                tracing::warn!("GeoLite2-City.mmdb not found (run scripts/fetch-geoip.ps1)");
            }
            if a.is_none() {
                tracing::warn!("GeoLite2-ASN.mmdb not found");
            }
            Arc::new(GeoIpResolver::empty())
        }
    }
}

fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1])))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}
