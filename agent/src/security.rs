//! Request guard for the local agent.
//!
//! The agent listens on loopback, but loopback is reachable from *any*
//! web page the user opens: a malicious site could fetch the API, open
//! the WebSocket or POST to mutating endpoints (start/stop capture,
//! firewall rules…). Two checks close that hole:
//!
//! 1. **Origin allowlist** — browsers attach `Origin` to every
//!    cross-origin request and to every WebSocket handshake. We only
//!    accept origins whose host is loopback (`localhost`, `127.0.0.1`,
//!    `[::1]`, any port: a remote site can never have such an origin)
//!    plus anything passed with `--allow-origin`. Requests *without*
//!    `Origin` (curl, same-origin GET navigations) are allowed.
//!
//! 2. **Host allowlist** — defeats DNS rebinding, where an attacker's
//!    domain is re-pointed at 127.0.0.1 so the page becomes
//!    "same-origin" with the agent and no `Origin` header is sent. The
//!    `Host` header still carries the attacker's domain, so we reject any
//!    `Host` that isn't loopback / the listen IP / `--allow-host`.
//!
//! Rejections happen *before* the handler runs, so even "simple" POSTs
//! that bypass CORS preflight never reach the capture or firewall code.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Exact origins allowed in addition to loopback ones, normalised
    /// (lower-case, no trailing slash), e.g. `http://192.168.1.10:3000`.
    pub extra_origins: Vec<String>,
    /// Extra hostnames accepted in the `Host` header (lower-case, no port).
    pub extra_hosts: Vec<String>,
    /// The IP the agent is bound to (also accepted as a `Host`).
    pub listen_ip: IpAddr,
}

impl SecurityConfig {
    pub fn new(listen: SocketAddr, allow_origins: &[String], allow_hosts: &[String]) -> Self {
        Self {
            extra_origins: allow_origins
                .iter()
                .map(|o| o.trim().trim_end_matches('/').to_ascii_lowercase())
                .filter(|o| !o.is_empty())
                .collect(),
            extra_hosts: allow_hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            listen_ip: listen.ip(),
        }
    }

    /// Is this `Origin` header value allowed?
    pub fn origin_allowed(&self, origin: &str) -> bool {
        let origin = origin.trim().trim_end_matches('/').to_ascii_lowercase();
        if self.extra_origins.iter().any(|o| *o == origin) {
            return true;
        }
        let rest = match origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
        {
            Some(r) => r,
            None => return false, // "null", file://, chrome-extension://…
        };
        // Origins have no path; keep authority only to be safe.
        let authority = rest.split('/').next().unwrap_or("");
        is_loopback_host(strip_port(authority))
    }

    /// Is this `Host` header value allowed?
    pub fn host_allowed(&self, host: &str) -> bool {
        let host = host.trim().to_ascii_lowercase();
        let name = strip_port(&host);
        if is_loopback_host(name) {
            return true;
        }
        if self.extra_hosts.iter().any(|h| h == name) {
            return true;
        }
        let bare = name.trim_start_matches('[').trim_end_matches(']');
        matches!(bare.parse::<IpAddr>(), Ok(ip) if ip == self.listen_ip && !ip.is_unspecified())
    }
}

/// `example.com:8080` → `example.com`, `[::1]:8088` → `[::1]`, `[::1]` → `[::1]`.
fn strip_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        match authority.find(']') {
            Some(end) => &authority[..=end],
            None => authority,
        }
    } else {
        match authority.rsplit_once(':') {
            // Only treat the suffix as a port if it's numeric.
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => authority,
        }
    }
}

fn is_loopback_host(name: &str) -> bool {
    if name == "localhost" || name.ends_with(".localhost") {
        return true;
    }
    let bare = name.trim_start_matches('[').trim_end_matches(']');
    matches!(bare.parse::<IpAddr>(), Ok(ip) if ip.is_loopback())
}

/// axum middleware enforcing the Host + Origin allowlists.
pub async fn guard(
    State(cfg): State<Arc<SecurityConfig>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(host) = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()) {
        if !cfg.host_allowed(host) {
            tracing::warn!("rejected request with Host {host:?} (possible DNS rebinding)");
            return forbidden("host not allowed");
        }
    }
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let ok = origin.to_str().map(|o| cfg.origin_allowed(o)).unwrap_or(false);
        if !ok {
            tracing::warn!("rejected request from origin {origin:?}");
            return forbidden("origin not allowed");
        }
    }
    next.run(req).await
}

/// Predicate for the CORS layer (same rules as the guard).
pub fn cors_predicate(cfg: Arc<SecurityConfig>) -> impl Fn(&HeaderValue) -> bool + Clone {
    move |origin: &HeaderValue| {
        origin
            .to_str()
            .map(|o| cfg.origin_allowed(o))
            .unwrap_or(false)
    }
}

fn forbidden(msg: &str) -> Response {
    let body = serde_json::json!({ "error": msg }).to_string();
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SecurityConfig {
        SecurityConfig::new(
            "127.0.0.1:8088".parse().unwrap(),
            &["http://192.168.1.20:3000/".to_string()],
            &["packet-eye.lan".to_string()],
        )
    }

    #[test]
    fn loopback_origins_are_allowed_on_any_port() {
        let c = cfg();
        for o in [
            "http://127.0.0.1:8088",
            "http://localhost:1420",
            "http://localhost:3000",
            "http://[::1]:8088",
            "https://localhost",
            "HTTP://LOCALHOST:4173",
        ] {
            assert!(c.origin_allowed(o), "{o} should be allowed");
        }
    }

    #[test]
    fn remote_and_odd_origins_are_rejected() {
        let c = cfg();
        for o in [
            "https://evil.com",
            "http://localhost.evil.com",
            "http://127.0.0.1.evil.com:8088",
            "null",
            "file://",
            "chrome-extension://abc",
            "http://192.168.1.20:3001",
        ] {
            assert!(!c.origin_allowed(o), "{o} should be rejected");
        }
    }

    #[test]
    fn explicit_extra_origin_is_allowed() {
        assert!(cfg().origin_allowed("http://192.168.1.20:3000"));
    }

    #[test]
    fn host_header_rules() {
        let c = cfg();
        assert!(c.host_allowed("127.0.0.1:8088"));
        assert!(c.host_allowed("localhost:8088"));
        assert!(c.host_allowed("[::1]:8088"));
        assert!(c.host_allowed("packet-eye.lan:8088"));
        assert!(!c.host_allowed("evil.com:8088"));
        assert!(!c.host_allowed("rebind.attacker.net"));
    }

    #[test]
    fn listen_ip_is_accepted_as_host() {
        let c = SecurityConfig::new("192.168.1.5:8088".parse().unwrap(), &[], &[]);
        assert!(c.host_allowed("192.168.1.5:8088"));
        assert!(!c.host_allowed("192.168.1.6:8088"));
        let any = SecurityConfig::new("0.0.0.0:8088".parse().unwrap(), &[], &[]);
        assert!(!any.host_allowed("0.0.0.0:8088"));
    }
}
