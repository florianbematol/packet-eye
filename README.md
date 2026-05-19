# Packet Eye

Real-time network monitoring with a 3D globe UI. Web app (any modern
browser) talking to a small Rust agent that captures packets locally
via Npcap on Windows.

📚 **Full documentation: <https://florianbematol.github.io/packet-eye/>**

![status](https://img.shields.io/badge/status-alpha-orange)
![license](https://img.shields.io/badge/license-MIT-blue)

---

## Architecture

```
+----------------------+        WebSocket /ws         +----------------------+
|  Browser (Chrome,    |  <-------------------------- |  packet-eye-agent    |
|  Firefox, Edge)      |  REST  /api/* (start, list…) |  (Rust + axum)       |
|  React + shadcn/ui   |  --------------------------> |  pcap + Npcap        |
|  + Three.js (globe)  |                              |  GeoIP enrichment    |
+----------------------+                              +----------------------+
```

## Features

- Live packet capture on any network interface, with the same
  fidelity as Wireshark (Npcap, full snaplen, promiscuous, no
  protocol pre-filter).
- 3D globe (NASA Blue Marble) with animated arcs / hotspots,
  user-resizable / draggable panels.
- GeoIP enrichment (country, city, lat/lon, ASN + organisation) using
  GeoLite2 City + ASN databases sourced from the
  [P3TERX mirror](https://github.com/P3TERX/GeoLite.mmdb) (no MaxMind
  account required).
- Process-level attribution on Windows
  (`GetExtendedTcpTable` / `GetExtendedUdpTable`).
- Threat-list checks (Spamhaus DROP, FireHOL Level 1, Tor exit nodes,
  user-defined `custom.txt`) with configurable alert rules and
  synthesised audio cues.
- Wireshark-style hex dump for any captured packet.
- Code-split, lazy-loaded SPA with shadcn/ui + Tailwind.

## Quick start

Prerequisites:

- Windows 10/11, Visual Studio 2022 Build Tools (C++), Rust stable,
  Node.js 18+.
- [Npcap runtime](https://npcap.com/dist/npcap-1.79.exe) (system
  install).
- [Npcap SDK](https://npcap.com/#download) extracted to
  `C:\npcap-sdk` (build-time only).

Set up:

```powershell
# JS deps
npm install
# Fetch GeoLite2 City + ASN databases (~75 MB)
npm run fetch-geoip
```

Run the agent (must be Administrator):

```powershell
npm run agent:run
```

In another terminal, run the dev frontend:

```powershell
npm run dev
# -> http://localhost:1420
```

For more, see the
[Installation](https://florianbematol.github.io/packet-eye/guide/install/)
and
[Running the app](https://florianbematol.github.io/packet-eye/guide/running/)
sections of the docs.

## Layout

```text
packet-eye/
├── agent/             Rust agent (capture + enrichment + REST/WS)
├── src/               React frontend
├── public/textures/   Earth textures
├── docs/              MkDocs documentation
├── scripts/           PowerShell helpers (cargo wrapper, GeoIP fetcher)
└── .github/workflows/ CI (docs deploy)
```

## License

MIT — see [LICENSE](./LICENSE).

GeoIP data is © MaxMind under the
[GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula),
redistributed via the P3TERX mirror.

Earth imagery is in the public domain (NASA Visible Earth).

Threat lists belong to their respective authors:
[Spamhaus](https://www.spamhaus.org/),
[FireHOL](https://iplists.firehol.org/),
[The Tor Project](https://www.torproject.org/).
