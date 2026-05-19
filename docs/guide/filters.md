# Capture filters

Packet Eye uses [Berkeley Packet Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
expressions, exactly like Wireshark and `tcpdump`. The Capture panel on
the left builds the BPF for you from three toggles, and shows you the
result so you always know what's being captured.

## The three toggles

| Toggle | What it adds back |
|---|---|
| **Include LAN traffic (RFC1918)** | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, IPv6 link-local (`fe80::/10`) and ULA (`fc00::/7`). |
| **Include localhost** | `127.0.0.0/8`, `::1`. |
| **Include broadcast / multicast** | `255.255.255.255`, `224.0.0.0/4` (IPv4 multicast), `ff00::/8` (IPv6 multicast). |

When a toggle is **off**, the corresponding range is excluded from the
BPF expression.

## Defaults

All three toggles default to **on** — meaning the agent captures
everything by default, just like Wireshark. Turn them off if you want
to focus on Internet-facing traffic only.

## Non-IP traffic

ARP, ICMPv6 NDP and other layer-2 frames **always** pass through, no
matter what the toggles say. They're listed in the connections table
under the `other` protocol with zeroed IPs/ports — but their full hex
dump is available in the inspector (handy for spotting ARP poisoning
or weird neighbour discovery patterns).

## Custom BPF

Below the toggles there's a free-text **Custom BPF** field that's
appended (with `and`) to the auto-generated expression. Some examples:

- `tcp port 443` — only HTTPS
- `host 8.8.8.8` — only traffic to/from Google's resolver
- `not arp` — drop ARP frames (overrides the always-on rule above)
- `udp and dst port 53` — outbound DNS queries

The full BPF grammar is described in
[`pcap-filter(7)`](https://www.tcpdump.org/manpages/pcap-filter.7.html).

## Reading the active BPF box

The panel always shows the **exact** filter expression the agent is
about to send to libpcap. Useful when troubleshooting "why don't I see
traffic X?". A typical expression with all toggles off looks like:

```text
not (ip and net 127.0.0.0/8) and not (ip6 and host ::1)
and not (ip and net 10.0.0.0/8) and …
```

If the box says `(no filter — capture everything)` you're literally
capturing everything Npcap delivers.

## Capture-time settings (not exposed)

- **snaplen** = `65535` (full Ethernet MTU, no truncation).
- **promisc** = `true` (off by default in libpcap, but we mirror
  Wireshark's behaviour).
- **immediate mode** = `true` (no kernel-side buffering delay).
- **buffer** = 8 MiB.

These aren't settable from the UI today — open an issue if you need
them tunable.
