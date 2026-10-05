# REST API

Base URL: `http://127.0.0.1:8088` (override with `--listen`).

All responses are JSON. Errors come back with an HTTP status ≥ 400 and
`{"error": "..."}` in the body.

Every request is checked against the Origin / Host allowlists first;
rejected requests get `403 {"error": "origin not allowed"}` (or
`host not allowed`). See [Security](../guide/security.md).

## Health

### `GET /api/health`

Returns the literal string `ok` (200) when the agent is up.

## Self lookup

### `GET /api/self`

Resolves the host's public IP via a fallback chain (ipify →
ifconfig.me → icanhazip), then runs it through the GeoIP resolver.

Cached in memory for 5 minutes.

```json
{
  "ip": "203.0.113.42",
  "geo": {
    "country": "France",
    "country_iso": "FR",
    "city": "Paris",
    "lat": 48.8566,
    "lon": 2.3522,
    "asn": 12876,
    "asn_org": "OVH SAS"
  }
}
```

`ip` may be `null` if all echo services time out; `geo` may be `null`
if the GeoIP database isn't loaded.

## Capture

### `GET /api/devices`

Lists all interfaces visible to libpcap.

```json
[
  {
    "name": "\\Device\\NPF_{21B8BC29-...}",
    "description": "Wi-Fi",
    "addresses": ["192.168.1.42", "fe80::1"],
    "flags": 4096,
    "is_loopback": false
  }
]
```

### `POST /api/capture/start`

Starts the capture thread. Body:

```json
{
  "device": "\\Device\\NPF_{...}",
  "filter": {
    "include_lan": true,
    "include_localhost": true,
    "include_broadcast": true,
    "custom": "tcp port 443"
  }
}
```

`filter` is optional; missing fields default to `true` (capture
everything). Returns `{ "running": true }`. Returns 409 if a capture
is already running.

### `POST /api/capture/stop`

Stops the running capture, joins the thread. Returns `{ "running":
false }`. Idempotent.

### `GET /api/capture/status`

Returns `{ "running": true|false }`.

### `GET /api/stats`

```json
{
  "stats": {
    "ts_ms": 1700000000000,
    "packets_per_sec": 1834.2,
    "bytes_per_sec": 982341.0,
    "active_connections": 0,
    "total_packets": 91234,
    "total_bytes": 12345678
  },
  "running": true
}
```

`active_connections` is left at 0 here — the frontend computes it from
the live connections map.

## Alerts

### `GET /api/alerts/rules`

Returns the current rule set.

### `PUT /api/alerts/rules`

Replaces the rule set. Body matches the GET shape:

```json
{
  "enabled": true,
  "threat_list": true,
  "burst": true,
  "burst_threshold_pps": 500,
  "suspicious_port": true,
  "suspicious_ports": [23, 445, 1337, 3389, 4444, 5555, 6666, 6667, 31337],
  "new_process_external": false,
  "new_asn": false,
  "new_country": true
}
```

Persisted to
`%APPDATA%\packet-eye\packet-eye\config\alert-rules.json`.

### `GET /api/threats`

```json
{
  "total_ranges": 4601,
  "dir": "C:\\…\\agent\\resources\\threat-lists",
  "lists": [
    {
      "id": "spamhaus_drop",
      "label": "Spamhaus DROP",
      "file": "spamhaus-drop.txt",
      "exists": true,
      "size_bytes": 45655,
      "modified_iso": "2026-10-05T17:20:11Z",
      "entries": 1532,
      "updatable": true
    }
  ]
}
```

`total_ranges` is the number of merged IPv4/IPv6 ranges in memory;
`entries` counts the lines of each file. `custom.txt` has
`"updatable": false`.

### `POST /api/threats/update`

Downloads Spamhaus DROP, FireHOL Level 1 and the Tor exit list into
`dir` (atomic rename per file), then hot-reloads every list including
`custom.txt`. A failing download keeps the previous file. `409` if an
update is already running.

```json
{
  "results": [
    { "file": "spamhaus-drop.txt", "ok": true, "error": null, "size_bytes": 45655 }
  ],
  "info": { "total_ranges": 4601, "dir": "…", "lists": [ … ] }
}
```

## Export

### `GET /api/export/info`

```json
{
  "frames": 18234,
  "bytes": 9123456,
  "budget_bytes": 67108864,
  "evicted_frames": 0,
  "oldest_ts_ms": 1700000000000,
  "newest_ts_ms": 1700000060000
}
```

### `GET /api/export/pcapng`

Returns the buffered frames as a `.pcapng` file
(`Content-Disposition: attachment`, `X-Packet-Count` header). Optional
filter, all three or none:

| Param | Example |
|---|---|
| `proto` | `tcp`, `udp`, `icmp` |
| `a` | `192.168.1.10:50000` or `[2001:db8::1]:443` |
| `b` | the other endpoint |

`404` when no buffered frame matches, `400` for bad parameters.

## History

All query endpoints accept `from` / `to` (Unix seconds, default the
last 24 h) and `limit` (default 200, max 5000).

| Endpoint | Extra params | Returns |
|---|---|---|
| `GET /api/history/timeline` | `bucket` (seconds, ≥ 60), `process` | `[{ts, packets, bytes, endpoints}]` |
| `GET /api/history/flows` | `q` (search), `process` | Top remote endpoints by bytes: proto, remote IP/port, process, domain, geo, ASN, packets, bytes, first/last seen. |
| `GET /api/history/apps` | — | Per process: packets, bytes, endpoints, countries, domains, first/last seen. |
| `GET /api/history/alerts` | — | `[{ts_ms, severity, rule, message, remote_ip}]`, newest first. |
| `GET /api/history/info` | — | DB path, size, row counts, oldest/newest minute, settings. |
| `GET/PUT /api/history/settings` | body `{enabled, retention_days}` | Saved settings (retention clamped to 1–365). |
| `POST /api/history/clear` | — | Deletes all rows, returns `info`. |

## Firewall

Windows only. Mutations need the agent to run as Administrator
(`403` otherwise).

### `GET /api/firewall/rules`

```json
[
  {
    "id": "{8A2B5C1E-…}",
    "name": "Packet Eye - block 203.0.113.7 (outbound)",
    "description": "Created by Packet Eye on 2026-10-05T17:30:00Z. Ads",
    "enabled": true,
    "direction": "Outbound",
    "action": "Block",
    "remote": ["203.0.113.7"],
    "program": "Any"
  }
]
```

### `POST /api/firewall/rules`

```json
{
  "target": { "kind": "ip", "value": "203.0.113.7, 198.51.100.0/24" },
  "direction": "out",
  "note": "optional"
}
```

`target` is one of `{"kind":"ip","value":…}`,
`{"kind":"program","path":"C:\\…\\app.exe"}` or
`{"kind":"process","pid":1234,"name":"app.exe"}` (path resolved from
the running process). `direction` is `out` (default), `in` or `both`
(two rules). Returns `{ "created": [ids], "rules": [ … ] }`.

### `PATCH /api/firewall/rules/:id`

Body `{"enabled": false}`. Returns the updated rule list.

### `DELETE /api/firewall/rules/:id`

Returns the updated rule list. Only rules of the `Packet Eye` group can
be changed or deleted (`404` otherwise).

## GeoIP

### `GET /api/geoip/info`

Reports which `.mmdb` file is currently active for City and ASN, where
it lives, and where override files would be written.

```json
{
  "city": {
    "filename": "GeoLite2-City.mmdb",
    "path": "C:\\…\\agent\\resources\\GeoLite2-City.mmdb",
    "exists": true,
    "size_bytes": 65982658,
    "modified_iso": "2026-05-18T20:10:34Z",
    "source": "cwd"
  },
  "asn": {
    "filename": "GeoLite2-ASN.mmdb",
    "path": "...",
    "exists": true,
    "size_bytes": 12186916,
    "modified_iso": "2026-05-18T20:10:34Z",
    "source": "cwd"
  },
  "override_dir": "C:\\Users\\<you>\\AppData\\Roaming\\packet-eye\\packet-eye\\data\\geoip"
}
```

`source` is one of `override`, `cwd`, `exe`, `missing`.

### `POST /api/geoip/update`

Downloads both `.mmdb` files from the P3TERX mirror, atomic-renames
them into `override_dir`, then hot-reloads the GeoIP resolver. Returns
`409` if another update is already running.

```json
{
  "ok": true,
  "elapsed_ms": 18342,
  "city": { ... },
  "asn":  { ... }
}
```
