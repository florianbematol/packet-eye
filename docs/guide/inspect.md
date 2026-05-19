# Inspecting connections

You have two ways to drill into a connection:

1. **Click a hotspot on the globe.** The marker lights up white, an
   info card opens at the bottom of the screen.
2. **Click a row in the *Live connections* table.** The row is
   highlighted in cyan, the same info card opens.

Click the same target a second time (or hit ✕) to close.

## The selection panel

It floats over the globe and is **draggable** — grab the slim handle
bar at the top to move it anywhere on screen. Position is persisted
to localStorage, so it stays put across reloads.

What's inside:

| Section | What it shows |
|---|---|
| **Identity** | Protocol badge, direction, hostname (or IP) + port. |
| **Location** | Country (ISO code + full name) and city, from GeoLite2-City. |
| **Coordinates** | Lat / lon used to place the hotspot. |
| **ASN** | `AS<number>` + organisation name, from GeoLite2-ASN. |
| **Process** | Owner process name + PID, from `GetExtendedTcpTable` / `GetExtendedUdpTable`. |
| **Live counters** | Current `bps`, total bytes, total packets. |
| **Tracked for** | Time since the first packet for this 5-tuple. |
| **Endpoints** | Raw `local_ip:port ↔ remote_ip:port`. |

## Recent packets

The bottom of the panel lists up to **50 of the most recent packets**
for this connection, in reverse order (newest first). For each packet:

- **time** — `HH:MM:SS.mmm` precision.
- **direction** — ↑ outbound (cyan), ↓ inbound (pink), · unknown.
- **flags** — for TCP, the textual flags (`SYN`, `ACK`, `PSH`, `FIN`,
  `RST`, `URG`). For UDP/ICMP, the protocol name.
- **size** — frame size in bytes.

Click a row to expand a **hex dump** below it.

## The hex dump

A classic Wireshark-style block:

```text
0000  45 00 00 28 1c 46 40 00  40 06 b1 e6 c0 a8 00 68   E..(.F@.@......h
0010  08 08 08 08 d2 ec 01 bb  ff bb a4 7c 00 00 00 00   ...........|....
…
```

The first 256 bytes of the raw frame are streamed from the agent in
hex form. Larger packets are truncated at this cap to keep WebSocket
messages small. If you need full payloads, file an issue and we'll
extend the snaplen / move to a per-packet detail endpoint.

## Tip: search for a specific endpoint

The connections table is sortable (click a header) and resizable (drag
between two header cells). Sort by ASN to group everything Cloudflare,
or by `bps` to find the noisiest connection. Then click the row → the
panel jumps to it on the globe.
