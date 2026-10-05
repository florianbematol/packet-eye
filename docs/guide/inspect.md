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
| **Identity** | Protocol badge, direction, remote IP + port, server location. |
| **Domain** | The name the application asked for (`download.xboxlive.com`…) and where it was read: TLS SNI, HTTP Host or DNS answer. See below. |
| **Firewall** | A red banner when a Packet Eye firewall rule blocks this IP or app. |
| **Coordinates** | Lat / lon used to place the hotspot (links to Google Maps). |
| **ASN** | `AS<number>` + organisation name, from GeoLite2-ASN. |
| **Process** | Owner process name + PID, from `GetExtendedTcpTable` / `GetExtendedUdpTable`. |
| **Live counters** | Current `bps`, total bytes, total packets. |
| **Tracked for** | Time since the first packet for this 5-tuple. |
| **Actions** | `.pcapng` export of this connection, *Block IP*, *Block app*. |

## Domain names

Packet Eye doesn't use reverse DNS (which returns CDN junk such as
`a23-45.deploy.static.akamaitechnologies.com`). It reads the name the
application really requested, straight from the captured traffic:

| Source | How | Coverage |
|---|---|---|
| **TLS SNI** | Server name in the clear-text ClientHello that opens every HTTPS connection. Hellos split over several TCP segments are reassembled. | Most HTTPS traffic, exact per connection. |
| **HTTP Host** | `Host:` header of plain-HTTP requests. | Unencrypted HTTP. |
| **DNS answer** | A / AAAA records in DNS responses map an IP back to the queried name. | Anything resolved through classic DNS while the capture runs. |

Limits: connections opened before the capture started only get a name
from DNS (if a lookup happens later); QUIC / HTTP-3, Encrypted Client
Hello and DNS-over-HTTPS hide the name.

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
hex form. For the full packets, export the connection as `.pcapng`
(see [Export to Wireshark](export.md)).

## Tip: search for a specific endpoint

The connections table is sortable (click a header) and resizable (drag
between two header cells). Sort by ASN to group everything Cloudflare,
by `domain` to group a service, or by `bps` to find the noisiest
connection. Then click the row → the panel jumps to it on the globe.
