# WebSocket protocol

Endpoint: `ws://127.0.0.1:8088/ws`. The handshake is rejected (`403`)
unless its `Origin` is a loopback origin or one passed with
`--allow-origin` — see [Security](../guide/security.md).

The client never sends anything; the server pushes JSON-encoded
messages.

## Message envelope

Every frame is a `Message::Text` carrying:

```json
{ "type": "<kind>", "data": <payload> }
```

with `kind` being one of:

| `type` | Cadence | Payload |
|---|---|---|
| `packets` | every batch (≤ 500 ms or 4096 packets) | array of `EnrichedPacket` |
| `stats` | every 1 s, plus once on connect | a `StatsTick` object |
| `alerts` | as alerts fire | array of `Alert` |

When you connect, the server sends one `stats` snapshot immediately so
the UI has numbers right away.

## EnrichedPacket

```ts
interface EnrichedPacket {
  ts_ms: number;          // capture timestamp, ms since epoch
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: "tcp" | "udp" | "icmp" | "other";
  len: number;            // raw frame size in bytes
  tcp_flags: number;      // packed bits, 0 for non-TCP
  direction: "inbound" | "outbound" | "unknown";
  src: SideInfo;
  dst: SideInfo;
  process?: string | null;
  pid?: number | null;
  domain?: string | null;       // remote domain, see below
  domain_source?: "sni" | "http" | "dns" | null;
  payload_hex?: string | null;  // ≤ 256 bytes hex-encoded
}

interface SideInfo {
  geo?: GeoLookup | null;
}

interface GeoLookup {
  country?: string | null;
  country_iso?: string | null;
  city?: string | null;
  lat?: number | null;
  lon?: number | null;
  asn?: number | null;
  asn_org?: string | null;
}
```

## TCP flags

```text
0b0000_0001  FIN
0b0000_0010  SYN
0b0000_0100  RST
0b0000_1000  PSH
0b0001_0000  ACK
0b0010_0000  URG
```

## StatsTick

```ts
interface StatsTick {
  ts_ms: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  active_connections: number;
  total_packets: number;
  total_bytes: number;
}
```

## Alert

```ts
type Severity = "critical" | "high" | "medium" | "low" | "info";

interface Alert {
  ts_ms: number;
  severity: Severity;
  rule: string;            // "threat-list" | "burst" | ...
  message: string;
  remote_ip?: string | null;
  context?: Record<string, unknown> | null;
}
```

## Backpressure

The server uses `tokio::sync::broadcast` channels with a capacity of
4096 (packets) and 256 (alerts). If a client lags, **older messages
are dropped** and the lag is logged at `debug` level. The client
keeps streaming whatever's still available.

There is no per-message ACK and no replay — this is a "live tail" and
nothing else.

## Reconnection

`src/lib/ws.ts` implements an auto-reconnect loop with exponential
backoff (initial 750 ms, capped at 10 s). The frontend exposes a
small connection indicator in the header.
