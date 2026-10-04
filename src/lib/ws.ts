// Minimal auto-reconnecting WebSocket client for the agent.
//
// Usage:
//   const conn = createPacketStream({
//     onPackets: (batch) => store.ingest(batch),
//     onStats:   (tick)  => store.setStats(tick),
//     onStatus:  (s)     => setStatus(s),
//   });
//   // later:
//   conn.close();

import { agentReady, getAgentWsUrl } from "@/lib/api";
import type { Alert, EnrichedPacket, StatsTick, WsMessage } from "@/lib/types";

export type ConnStatus = "connecting" | "open" | "closed" | "error";

export interface PacketStreamOptions {
  onPackets?: (batch: EnrichedPacket[]) => void;
  onStats?: (tick: StatsTick) => void;
  onAlerts?: (alerts: Alert[]) => void;
  onStatus?: (s: ConnStatus) => void;
  /** Initial reconnect delay in ms (capped at 10s with backoff). */
  initialReconnectDelay?: number;
}

export interface PacketStream {
  close: () => void;
  status: () => ConnStatus;
}

export function createPacketStream(opts: PacketStreamOptions): PacketStream {
  let socket: WebSocket | null = null;
  let closed = false;
  let attempt = 0;
  let status: ConnStatus = "connecting";
  let connectTimer: number | null = null;

  const initialDelay = opts.initialReconnectDelay ?? 750;

  const setStatus = (s: ConnStatus) => {
    status = s;
    opts.onStatus?.(s);
  };

  const connect = () => {
    if (closed) return;
    setStatus("connecting");

    const url = getAgentWsUrl();
    const ws = new WebSocket(url);
    socket = ws;

    ws.addEventListener("open", () => {
      attempt = 0;
      setStatus("open");
    });

    ws.addEventListener("message", (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as WsMessage;
        if (msg.type === "packets") {
          opts.onPackets?.(msg.data);
        } else if (msg.type === "stats") {
          opts.onStats?.(msg.data);
        } else if (msg.type === "alerts") {
          opts.onAlerts?.(msg.data);
        }
      } catch (e) {
        console.warn("ws parse error", e);
      }
    });

    ws.addEventListener("error", () => {
      // Many transient errors fire right before "close" during normal
      // unmount/reconnect cycles. Promote to "error" only if we're not
      // already trying to close.
      if (!closed) setStatus("error");
    });

    ws.addEventListener("close", () => {
      if (closed) return;
      setStatus("closed");
      // Exponential backoff capped at 10s.
      attempt += 1;
      const delay = Math.min(initialDelay * 2 ** (attempt - 1), 10_000);
      connectTimer = window.setTimeout(connect, delay);
    });
  };

  // Wait for the agent URL to be resolved, then defer one tick so that
  // React 18 StrictMode's double-mount in dev doesn't immediately tear
  // down the socket while it's still in CONNECTING.
  agentReady().then(() => {
    if (!closed) connectTimer = window.setTimeout(connect, 0);
  });

  return {
    close: () => {
      closed = true;
      if (connectTimer != null) {
        clearTimeout(connectTimer);
        connectTimer = null;
      }
      // Only call close() on sockets that are past CONNECTING; calling
      // close() during the handshake produces a noisy warning in DevTools.
      if (socket) {
        if (
          socket.readyState === WebSocket.OPEN ||
          socket.readyState === WebSocket.CLOSING
        ) {
          socket.close();
        } else if (socket.readyState === WebSocket.CONNECTING) {
          // Suppress events from this in-flight socket and let the
          // browser GC it once the handshake completes/fails.
          socket.onopen = null;
          socket.onmessage = null;
          socket.onerror = null;
          socket.onclose = null;
          try {
            socket.close();
          } catch {
            /* ignore */
          }
        }
      }
    },
    status: () => status,
  };
}
