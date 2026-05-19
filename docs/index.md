# Packet Eye

Real-time network monitoring with a 3D globe UI. **Web app** (any modern
browser) talking to a small Rust agent that captures packets locally via
Npcap on Windows.

![hero](https://img.shields.io/badge/status-alpha-orange)
![license](https://img.shields.io/badge/license-MIT-blue)

---

## What it does

Packet Eye watches every IP packet your machine sends or receives, then:

- Decorates each connection with **GeoIP city + ASN** (MaxMind GeoLite2,
  via the [P3TERX mirror](https://github.com/P3TERX/GeoLite.mmdb), no
  account needed).
- Maps the local socket to the **owning process / PID** via Windows
  `GetExtendedTcpTable` / `GetExtendedUdpTable`.
- Streams the enriched events live to a browser UI featuring a textured
  3D Earth (NASA imagery), animated arcs between you and each remote
  endpoint, a sortable / resizable connections table, and a packet
  inspector with a Wireshark-style hex dump.
- Cross-checks every public destination IP against multiple
  **threat lists** (Spamhaus DROP, FireHOL Level 1, Tor exit nodes) and
  raises configurable alerts with optional sound feedback.

## Architecture in one sketch

```
+----------------------+        WebSocket /ws         +----------------------+
|  Browser (Chrome,    |  <-------------------------- |  packet-eye-agent    |
|  Firefox, Edge)      |  REST /api/* (start, list…)  |  (Rust + axum)       |
|  React + shadcn/ui   |  --------------------------> |  pcap + Npcap        |
|  + Three.js (globe)  |                              |  GeoIP enrichment    |
+----------------------+                              +----------------------+
```

The local agent (Rust binary) opens a libpcap/Npcap handle, parses
frames with `etherparse`, enriches them, then fans them out over a
WebSocket. The frontend is a vanilla SPA that talks to it on
`http://127.0.0.1:8088` — no cloud, no telemetry, your packets never
leave the box.

## Why?

A "what's my computer talking to?" tool that's:

- **Visual first** — DDoS-attack-map vibe, useful at a glance.
- **Local only** — no agent in the cloud, no remote inspection.
- **Free of accounts** — GeoIP via the public P3TERX mirror.

If you want a forensic packet analyser, use Wireshark. If you want a
live "where am I sending data right now" dashboard with hex inspection
and alerts when something fishy happens, this is for you.

---

Continue with [Installation](guide/install.md).
