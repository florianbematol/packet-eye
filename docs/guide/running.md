# Running the app

You need **two terminals**: one for the agent (must be Administrator),
one for the frontend dev server.

## Terminal 1 — agent

Run **PowerShell as Administrator**, then:

```powershell
cd C:\path\to\packet-eye
npm run agent:run
```

You should see something like:

```
INFO packet_eye_agent: packet-eye-agent starting on 127.0.0.1:8088
INFO packet_eye_agent::enrich::geoip: GeoIP databases loaded
INFO packet_eye_agent::threats::loader: threat lists loaded: 4445 ranges
INFO packet_eye_agent: listening on http://127.0.0.1:8088
```

If you see warnings like *"GeoLite2-City.mmdb not found"*, run
`npm run fetch-geoip` first.

If you launch the agent without admin privileges, capture will fail
once you press *Start* in the UI (Npcap requires elevation).

## Terminal 2 — frontend

Regular (non-admin) PowerShell:

```powershell
cd C:\path\to\packet-eye
npm run dev
```

Vite serves on `http://localhost:1420`. Open that URL in any modern
browser. The page connects to the agent's WebSocket automatically.

## CLI options for the agent

```text
packet-eye-agent --help

  --listen <ADDR>            default 127.0.0.1:8088
  --city-db  <PATH>          override GeoLite2-City.mmdb path
  --asn-db   <PATH>          override GeoLite2-ASN.mmdb path
  --allow-origin <ORIGIN>    extra web origin allowed to call the API (repeatable)
  --allow-host <HOST>        extra Host header accepted (repeatable)
  --pcap-buffer-mb <MiB>     raw-frame buffer for the .pcapng export (default 64, 0 = off)
  --ui <DIR>                 serve the web UI from this folder
  --no-ui                    API only
```

Pages served from `localhost`, `127.0.0.1` or `[::1]` (any port) are
always allowed to talk to the agent — so `npm run dev`, `npx serve dist`
or the agent itself all work out of the box. See
[Security](security.md) for the why and for exposing the agent on a LAN.

If you change `--listen`, set the matching env var for the frontend:

```powershell
# .env.local at the repo root, before `npm run dev`
VITE_AGENT_URL=http://127.0.0.1:9000
```

## Production build

```powershell
npm run build              # builds the SPA into ./dist
npm run agent:build        # release binary in agent/target/release
```

Then run **only the agent**, as Administrator, from the repo root:

```powershell
.\agent\target\release\packet-eye-agent.exe
```

The agent auto-detects `dist/` and serves the UI itself — open
<http://127.0.0.1:8088>. Use `--ui <dir>` to point at another build
folder, or `--no-ui` to expose the API only.

## Stopping

- Frontend: Ctrl+C in the Vite terminal.
- Agent: Ctrl+C, or close the elevated terminal. The capture thread
  shuts down cleanly via an `AtomicBool`.

Read on for [capture filters](filters.md).
