# REST API

Base URL: `http://127.0.0.1:8088` (override with `--listen`).

All responses are JSON. Errors come back with an HTTP status ≥ 400 and
`{"error": "..."}` in the body.

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
{ "total_ranges": 4445 }
```

The number of merged IPv4/IPv6 ranges currently loaded from the four
threat-list files.

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
