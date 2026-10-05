// Live state populated from the agent WebSocket.

import { create } from "zustand";
import type {
  EnrichedPacket,
  Protocol,
  Direction,
  StatsTick,
  GeoLookup,
  DomainSource,
} from "@/lib/types";

const RECENT_PACKET_CAP = 4096;
const CONNECTION_TTL_MS = 60_000;
const PRUNE_INTERVAL_MS = 5_000;

export interface ConnectionAgg {
  id: string;
  proto: Protocol;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  remote_ip: string;
  remote_port: number;
  remote_geo: GeoLookup | null;
  /** Domain learned from TLS SNI / HTTP Host / DNS (null if unknown). */
  remote_domain: string | null;
  remote_domain_source: DomainSource | null;
  process: string | null;
  pid: number | null;
  direction: Direction;
  first_seen_ms: number;
  last_seen_ms: number;
  packets: number;
  bytes: number;
  /** Bytes accumulated since the last rate-window reset. */
  bytes_window: number;
  /** Window-start timestamp (ms) for the rolling rate. */
  window_start_ms: number;
  /** Smoothed bytes/second over the latest 1s window. */
  bytes_per_sec: number;
  /** Set when an alert references this remote IP, decays over time. */
  flash_until_ms: number;
}

export interface StatsState {
  packets_per_sec: number;
  bytes_per_sec: number;
  active_connections: number;
  total_packets: number;
  total_bytes: number;
  last_tick_ms: number;
}

interface ConnectionsStoreState {
  recentPackets: EnrichedPacket[];
  connections: Map<string, ConnectionAgg>;
  stats: StatsState;
  ingestBatch: (batch: EnrichedPacket[]) => void;
  setStats: (tick: StatsTick) => void;
  flashRemote: (ip: string, durationMs?: number) => void;
  reset: () => void;
}

function pickRemote(p: EnrichedPacket): {
  remote_ip: string;
  remote_port: number;
  geo: GeoLookup | null;
} {
  if (p.direction === "outbound") {
    return {
      remote_ip: p.dst_ip,
      remote_port: p.dst_port,
      geo: p.dst.geo ?? null,
    };
  }
  if (p.direction === "inbound") {
    return {
      remote_ip: p.src_ip,
      remote_port: p.src_port,
      geo: p.src.geo ?? null,
    };
  }
  if (p.dst.geo && !p.src.geo) {
    return {
      remote_ip: p.dst_ip,
      remote_port: p.dst_port,
      geo: p.dst.geo,
    };
  }
  if (p.src.geo && !p.dst.geo) {
    return {
      remote_ip: p.src_ip,
      remote_port: p.src_port,
      geo: p.src.geo,
    };
  }
  return {
    remote_ip: p.dst_ip,
    remote_port: p.dst_port,
    geo: p.dst.geo ?? null,
  };
}

export function connKey(p: EnrichedPacket): string {
  const a = `${p.src_ip}:${p.src_port}`;
  const b = `${p.dst_ip}:${p.dst_port}`;
  const [low, high] = a < b ? [a, b] : [b, a];
  return `${p.proto}|${low}|${high}`;
}

export const useConnectionsStore = create<ConnectionsStoreState>((set, get) => ({
  recentPackets: [],
  connections: new Map(),
  stats: {
    packets_per_sec: 0,
    bytes_per_sec: 0,
    active_connections: 0,
    total_packets: 0,
    total_bytes: 0,
    last_tick_ms: 0,
  },

  ingestBatch: (batch: EnrichedPacket[]) => {
    if (!batch.length) return;
    const state = get();

    const recent = state.recentPackets.concat(batch);
    if (recent.length > RECENT_PACKET_CAP) {
      recent.splice(0, recent.length - RECENT_PACKET_CAP);
    }

    const conns = new Map(state.connections);
    const RATE_WINDOW_MS = 1000;

    for (const p of batch) {
      const k = connKey(p);
      const existing = conns.get(k);
      const remote = pickRemote(p);

      if (existing) {
        existing.last_seen_ms = p.ts_ms;
        existing.packets += 1;
        existing.bytes += p.len;

        // Sliding 1s window for bytes/s.
        const windowAge = p.ts_ms - existing.window_start_ms;
        if (windowAge >= RATE_WINDOW_MS) {
          // Close the previous window and open a new one.
          const secs = Math.max(0.001, windowAge / 1000);
          existing.bytes_per_sec = existing.bytes_window / secs;
          existing.bytes_window = p.len;
          existing.window_start_ms = p.ts_ms;
        } else {
          existing.bytes_window += p.len;
          // Optimistic estimate even before the window fully closes.
          if (windowAge > 50) {
            existing.bytes_per_sec = (existing.bytes_window / windowAge) * 1000;
          }
        }

        if (p.direction !== "unknown") existing.direction = p.direction;
        if (!existing.remote_geo && remote.geo) existing.remote_geo = remote.geo;
        if (p.domain) {
          existing.remote_domain = p.domain;
          existing.remote_domain_source = p.domain_source ?? null;
        }
        if (!existing.process && p.process) existing.process = p.process;
        if (!existing.pid && p.pid) existing.pid = p.pid;
      } else {
        conns.set(k, {
          id: k,
          proto: p.proto,
          src_ip: p.src_ip,
          src_port: p.src_port,
          dst_ip: p.dst_ip,
          dst_port: p.dst_port,
          remote_ip: remote.remote_ip,
          remote_port: remote.remote_port,
          remote_geo: remote.geo,
          remote_domain: p.domain ?? null,
          remote_domain_source: p.domain_source ?? null,
          process: p.process ?? null,
          pid: p.pid ?? null,
          direction: p.direction,
          first_seen_ms: p.ts_ms,
          last_seen_ms: p.ts_ms,
          packets: 1,
          bytes: p.len,
          bytes_window: p.len,
          window_start_ms: p.ts_ms,
          bytes_per_sec: 0,
          flash_until_ms: 0,
        });
      }
    }

    set({ recentPackets: recent, connections: conns });
  },

  flashRemote: (ip, durationMs = 4000) => {
    const state = get();
    if (state.connections.size === 0) return;
    const next = new Map(state.connections);
    const flashUntil = Date.now() + durationMs;
    let touched = false;
    for (const c of next.values()) {
      if (c.remote_ip === ip) {
        c.flash_until_ms = Math.max(c.flash_until_ms, flashUntil);
        touched = true;
      }
    }
    if (touched) set({ connections: next });
  },

  setStats: (tick: StatsTick) => {
    set({
      stats: {
        packets_per_sec: tick.packets_per_sec,
        bytes_per_sec: tick.bytes_per_sec,
        active_connections: tick.active_connections || get().connections.size,
        total_packets: tick.total_packets,
        total_bytes: tick.total_bytes,
        last_tick_ms: tick.ts_ms,
      },
    });
  },

  reset: () => {
    set({
      recentPackets: [],
      connections: new Map(),
      stats: {
        packets_per_sec: 0,
        bytes_per_sec: 0,
        active_connections: 0,
        total_packets: 0,
        total_bytes: 0,
        last_tick_ms: 0,
      },
    });
  },
}));

if (typeof window !== "undefined") {
  setInterval(() => {
    const state = useConnectionsStore.getState();
    const cutoff = Date.now() - CONNECTION_TTL_MS;
    if (state.connections.size === 0) return;
    let pruned = false;
    const next = new Map(state.connections);
    for (const [k, c] of next) {
      if (c.last_seen_ms < cutoff) {
        next.delete(k);
        pruned = true;
      }
    }
    if (pruned) {
      useConnectionsStore.setState({ connections: next });
    }
  }, PRUNE_INTERVAL_MS);
}
