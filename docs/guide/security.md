# Security

The agent runs as Administrator, captures all your traffic, and can
change firewall rules. It only listens on `127.0.0.1`, but that alone
isn't enough: **any web page open in your browser can send requests to
`127.0.0.1`**. Two checks run before every request reaches a handler.

## Origin allowlist

Browsers attach an `Origin` header to cross-site requests and to every
WebSocket handshake. The agent accepts only:

- origins whose host is loopback — `localhost`, `127.0.0.1`, `[::1]`,
  any port (a remote website can never have such an origin);
- origins passed with `--allow-origin`.

Anything else gets `403` — including "simple" POST requests that skip
the CORS preflight, so a malicious page can't even start/stop a capture
or create a firewall rule blindly. Requests without `Origin` (curl,
same-origin page loads) are allowed.

## Host allowlist (DNS rebinding)

In a DNS-rebinding attack, `evil.example` is re-pointed to `127.0.0.1`,
so the attacker's page becomes "same-origin" with the agent and no
`Origin` is sent. The `Host` header still says `evil.example`, so the
agent rejects any `Host` that isn't loopback, the listen IP, or a name
passed with `--allow-host`.

## Exposing the agent on a LAN

Not recommended — the API has no authentication. If you really want to
open the UI from another machine:

```powershell
packet-eye-agent --listen 0.0.0.0:8088 `
  --allow-host 192.168.1.10 `
  --allow-origin http://192.168.1.10:8088
```

The agent logs a warning at startup when it isn't bound to loopback.
Anyone on the network can then read your traffic and change your
firewall rules.

## What is stored on disk

| Path | Content |
|---|---|
| `%APPDATA%\packet-eye\packet-eye\data\history.sqlite` | Per-minute flow history and alerts (see [History](history.md)). |
| `%APPDATA%\packet-eye\packet-eye\config\*.json` | Alert rules and history settings. |
| `agent\resources\` | GeoIP databases and threat lists. |

Nothing is sent anywhere, except the public-IP lookup (`/api/self`),
and the GeoIP / threat-list downloads you trigger.
