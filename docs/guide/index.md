# Overview

Packet Eye is split into two pieces:

| Component | Tech | Role |
|---|---|---|
| **Agent** (`agent/`) | Rust + axum + libpcap (Npcap) | Captures and enriches packets, exposes a local HTTP + WebSocket API on `127.0.0.1:8088`. Must run as Administrator. |
| **Frontend** (`src/`) | React + Vite + shadcn/ui + Three.js | The web UI you open in your browser. Talks to the agent via REST + WS. |

The agent is the only thing that needs OS-level privileges. The
frontend is just a static SPA — once built, it's HTML + JS + CSS, no
server-side rendering.

## What you'll find in the docs

- **[Installation](install.md)** — what to install (Rust, Node, Npcap)
  and how to fetch the GeoIP databases.
- **[Running the app](running.md)** — bringing the agent and the dev
  frontend up.
- **[Capture filters](filters.md)** — the BPF expression that the
  Capture panel computes for you (and how to write your own).
- **[The 3D globe](globe.md)** — what each marker, arc and colour
  means, and the controls.
- **[Inspecting connections](inspect.md)** — clicking a hotspot or a
  table row, the per-connection panel, and the hex dump.
- **[Alerts & threat lists](alerts.md)** — the rule engine, the
  bundled lists, and the sound config.
- **[GeoIP databases](geoip.md)** — how the GeoLite2 City + ASN files
  are sourced, embedded and updated at runtime.
