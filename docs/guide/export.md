# Export to Wireshark (.pcapng)

While a capture runs, the agent keeps a copy of every raw frame in a
memory ring buffer (64 MiB by default, oldest frames dropped first).
You can download it as a standard `.pcapng` file and open it in
[Wireshark](https://www.wireshark.org/), `tshark` or any pcapng reader.

## Two ways to export

- **The whole buffer** — *Export .pcapng* button at the bottom of the
  Capture panel. It also shows how many packets / bytes are buffered.
- **One connection** — *.pcapng* button in the connection details
  panel. Only the frames of that 5-tuple (both directions) are written.

Files are named `packet-eye-YYYYMMDD-HHMMSS[-connection].pcapng`.

## What's in the file

- Full frames: the capture uses a 65535-byte snaplen, nothing is
  truncated.
- Microsecond timestamps from Npcap.
- The real link type of the interface (Ethernet, raw IP, loopback…).
- Every frame Npcap delivered — including ARP and other non-IP frames
  in the full export.

## Buffer size

```powershell
packet-eye-agent --pcap-buffer-mb 256   # bigger window
packet-eye-agent --pcap-buffer-mb 0     # disable (saves memory)
```

The buffer is cleared when a new capture starts. With heavy traffic
(a large download), 64 MiB covers only a few seconds to minutes; raise
it if you want a longer window.

## API

`GET /api/export/info` returns the buffer state;
`GET /api/export/pcapng[?proto=tcp&a=IP:PORT&b=IP:PORT]` returns the
file. See the [REST API](../reference/api.md#export).
