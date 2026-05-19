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

  --listen <ADDR>           default 127.0.0.1:8088
  --city-db  <PATH>         override GeoLite2-City.mmdb path
  --asn-db   <PATH>         override GeoLite2-ASN.mmdb path
  --permissive-cors         allow any origin (default true, for vite dev)
```

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

Serving the SPA from any static host (or even directly from `dist/`)
works as long as the agent is reachable from the browser. Since the
agent listens on `127.0.0.1` by default, the simplest deployment is
"same machine".

## Stopping

- Frontend: Ctrl+C in the Vite terminal.
- Agent: Ctrl+C, or close the elevated terminal. The capture thread
  shuts down cleanly via an `AtomicBool`.

Read on for [capture filters](filters.md).
