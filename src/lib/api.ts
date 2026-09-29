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
//   2. In production builds, the page's own origin — the agent serves the
//      UI itself, so API + WS live on the same host:port.
//   3. In `vite dev`, the default agent address.
const BASE_URL =
  (import.meta.env.VITE_AGENT_URL as string | undefined) ??
  (!import.meta.env.DEV && typeof window !== "undefined"
    ? window.location.origin
    : "http://127.0.0.1:8088");

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let err: unknown;
    try {
      err = await res.json();
    } catch {
      err = await res.text();
    }
    const msg = typeof err === "object" && err && "error" in err
      ? String((err as { error: unknown }).error)
      : String(err);
    throw new Error(`${res.status} ${res.statusText}: ${msg}`);
  }
  return (await res.json()) as T;
}

export const api = {
  health: () => fetch(`${BASE_URL}/api/health`).then((r) => r.ok),
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
