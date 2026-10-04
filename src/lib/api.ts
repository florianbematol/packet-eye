// Thin REST client for the Packet Eye local agent.
//
// Base URL is configurable via VITE_AGENT_URL (defaults to http://127.0.0.1:8088).
// At dev time you'll want to run vite + the agent side by side.

import type {
  AlertRules,
  CaptureFilter,
  DeviceInfo,
  GeoIpInfo,
  GeoIpUpdateResp,
  SelfResp,
  StatsTick,
  StatusResp,
  ThreatStats,
} from "@/lib/types";

// Resolution order:
//   1. VITE_AGENT_URL if set at build time.
//   2. In production builds, the page's own origin IF it's the agent
//      (i.e. `/api/health` answers "ok") — that's the case when the agent
//      serves the UI itself on any --listen address.
//   3. Otherwise the default agent address. This covers `vite dev` and
//      serving `dist/` from another static server (e.g. `npx serve`).
const DEFAULT_AGENT_URL = "http://127.0.0.1:8088";
const ENV_AGENT_URL = import.meta.env.VITE_AGENT_URL as string | undefined;

let BASE_URL = ENV_AGENT_URL ?? DEFAULT_AGENT_URL;

const ready: Promise<string> = (async () => {
  if (ENV_AGENT_URL || import.meta.env.DEV || typeof window === "undefined") {
    return BASE_URL;
  }
  const origin = window.location.origin;
  if (origin === DEFAULT_AGENT_URL) return (BASE_URL = origin);
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1500);
    const res = await fetch(`${origin}/api/health`, { signal: ctrl.signal });
    clearTimeout(timer);
    // Check the body too: SPA-fallback servers answer 200 with index.html.
    if (res.ok && (await res.text()).trim() === "ok") BASE_URL = origin;
  } catch {
    /* not the agent — keep the default */
  }
  return BASE_URL;
})();

/** Resolves once the agent base URL has been determined. */
export function agentReady(): Promise<string> {
  return ready;
}

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  await ready;
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    // Read the body exactly once (a Response body can't be consumed
    // twice), then try to interpret it as `{ "error": "..." }`.
    const raw = await res.text().catch(() => "");
    let msg = raw.trim() || res.statusText;
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (parsed && typeof parsed === "object" && "error" in parsed) {
        msg = String((parsed as { error: unknown }).error);
      }
    } catch {
      /* not JSON — keep the raw text */
    }
    throw new Error(`${res.status}: ${msg}`);
  }
  return (await res.json()) as T;
}

export const api = {
  health: () =>
    ready.then(() => fetch(`${BASE_URL}/api/health`)).then((r) => r.ok),
  self: () => request<SelfResp>("/api/self"),
  listDevices: () => request<DeviceInfo[]>("/api/devices"),
  status: () => request<StatusResp>("/api/capture/status"),
  stats: () => request<{ stats: StatsTick; running: boolean }>("/api/stats"),
  startCapture: (device: string, filter?: CaptureFilter) =>
    request<StatusResp>("/api/capture/start", {
      method: "POST",
      body: JSON.stringify({ device, filter: filter ?? {} }),
    }),
  stopCapture: () =>
    request<StatusResp>("/api/capture/stop", { method: "POST" }),
  getRules: () => request<AlertRules>("/api/alerts/rules"),
  putRules: (rules: AlertRules) =>
    request<AlertRules>("/api/alerts/rules", {
      method: "PUT",
      body: JSON.stringify(rules),
    }),
  threatStats: () => request<ThreatStats>("/api/threats"),
  geoipInfo: () => request<GeoIpInfo>("/api/geoip/info"),
  geoipUpdate: () =>
    request<GeoIpUpdateResp>("/api/geoip/update", { method: "POST" }),
};

export function getAgentBaseUrl(): string {
  return BASE_URL;
}

export function getAgentWsUrl(): string {
  // Convert http(s) -> ws(s).
  return BASE_URL.replace(/^http/, "ws") + "/ws";
}
