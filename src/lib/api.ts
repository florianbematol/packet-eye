// Thin REST client for the Packet Eye local agent.
//
// Base URL is configurable via VITE_AGENT_URL (defaults to http://127.0.0.1:8088).
// At dev time you'll want to run vite + the agent side by side.

import type {
  AlertRules,
  BlockDirection,
  BlockTarget,
  CaptureFilter,
  DeviceInfo,
  FirewallRule,
  GeoIpInfo,
  GeoIpUpdateResp,
  HistoryAlert,
  HistoryApp,
  HistoryFlow,
  HistoryInfo,
  HistoryQuery,
  HistorySettings,
  RingInfo,
  SelfResp,
  StatsTick,
  StatusResp,
  ThreatStats,
  ThreatUpdateResp,
  TimelinePoint,
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
  threatsUpdate: () =>
    request<ThreatUpdateResp>("/api/threats/update", { method: "POST" }),
  geoipInfo: () => request<GeoIpInfo>("/api/geoip/info"),
  geoipUpdate: () =>
    request<GeoIpUpdateResp>("/api/geoip/update", { method: "POST" }),

  // ---- Export ----
  exportInfo: () => request<RingInfo>("/api/export/info"),

  // ---- History ----
  historyInfo: () => request<HistoryInfo>("/api/history/info"),
  historyTimeline: (q: HistoryQuery) =>
    request<TimelinePoint[]>(`/api/history/timeline${qs(q)}`),
  historyFlows: (q: HistoryQuery) =>
    request<HistoryFlow[]>(`/api/history/flows${qs(q)}`),
  historyApps: (q: HistoryQuery) =>
    request<HistoryApp[]>(`/api/history/apps${qs(q)}`),
  historyAlerts: (q: HistoryQuery) =>
    request<HistoryAlert[]>(`/api/history/alerts${qs(q)}`),
  historySettings: (s: HistorySettings) =>
    request<HistorySettings>("/api/history/settings", {
      method: "PUT",
      body: JSON.stringify(s),
    }),
  historyClear: () =>
    request<HistoryInfo>("/api/history/clear", { method: "POST" }),

  // ---- Firewall ----
  firewallRules: () => request<FirewallRule[]>("/api/firewall/rules"),
  firewallBlock: (target: BlockTarget, direction: BlockDirection, note?: string) =>
    request<{ created: string[]; rules: FirewallRule[] }>("/api/firewall/rules", {
      method: "POST",
      body: JSON.stringify({ target, direction, note: note || null }),
    }),
  firewallSetEnabled: (id: string, enabled: boolean) =>
    request<FirewallRule[]>(`/api/firewall/rules/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }),
  firewallDelete: (id: string) =>
    request<FirewallRule[]>(`/api/firewall/rules/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
};

/** Build a `?a=1&b=2` query string, skipping empty values. */
function qs(params: object): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

/** Format an endpoint the way the agent parses it (`[v6]:port`). */
export function endpoint(ip: string, port: number): string {
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/**
 * Download the buffered capture as `.pcapng`, optionally restricted to
 * one connection. Throws with the agent's message on failure.
 */
export async function downloadPcapng(flow?: {
  proto: string;
  a: string;
  b: string;
}): Promise<number> {
  await ready;
  const res = await fetch(`${BASE_URL}/api/export/pcapng${qs(flow ?? {})}`);
  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    let msg = raw || res.statusText;
    try {
      msg = (JSON.parse(raw) as { error?: string }).error ?? msg;
    } catch {
      /* keep raw */
    }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") ?? "";
  const name = /filename="([^"]+)"/.exec(disposition)?.[1] ?? "packet-eye.pcapng";
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
  return Number(res.headers.get("x-packet-count") ?? 0);
}

export function getAgentBaseUrl(): string {
  return BASE_URL;
}

export function getAgentWsUrl(): string {
  // Convert http(s) -> ws(s).
  return BASE_URL.replace(/^http/, "ws") + "/ws";
}
