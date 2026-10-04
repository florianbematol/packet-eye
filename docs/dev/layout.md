# Project layout

```text
packet-eye/
├── agent/                 # Rust capture agent (standalone binary)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs        # CLI entry (clap + tokio)
│   │   ├── lib.rs         # axum bootstrap, builds the app state
│   │   ├── state.rs       # AppState + broadcast channels
│   │   ├── api/           # HTTP + WebSocket handlers
│   │   │   ├── mod.rs
│   │   │   ├── capture.rs    # /api/devices, /api/capture/*, /api/stats
│   │   │   ├── alerts.rs     # /api/alerts/rules, /api/threats
│   │   │   ├── geoip.rs      # /api/geoip/info, /api/geoip/update
│   │   │   ├── self_ip.rs    # /api/self
│   │   │   └── ws.rs         # /ws (multiplexed packets/stats/alerts)
│   │   ├── capture/       # libpcap loop + parsing
│   │   │   ├── runner.rs
│   │   │   ├── device.rs
│   │   │   ├── bpf.rs
│   │   │   └── types.rs
│   │   ├── enrich/        # GeoIP / process / DNS / local-ips
│   │   │   ├── mod.rs
│   │   │   ├── geoip.rs
│   │   │   ├── process.rs
│   │   │   ├── dns.rs
│   │   │   └── local_ips.rs
│   │   ├── threats/       # Threat-list loader + matcher
│   │   │   ├── mod.rs
│   │   │   ├── loader.rs
│   │   │   └── matcher.rs
│   │   └── alerts/        # Rule engine
│   │       ├── mod.rs
│   │       ├── engine.rs
│   │       └── rules.rs
│   └── resources/         # GeoIP databases + threat lists + sounds
│
├── src/                   # React frontend (see reference/frontend.md)
├── public/textures/       # Earth textures (Natural Earth III 16K day/lights/bump/water + 8K clouds)
├── scripts/
│   ├── cargo.ps1          # PATH-aware cargo wrapper used by npm scripts
│   ├── fetch-geoip.ps1    # Pulls GeoLite2 mmdb files from P3TERX
│   └── fetch-threats.ps1  # Pulls Spamhaus / FireHOL / Tor threat lists
├── docs/                  # MkDocs site sources (this site)
├── mkdocs.yml
├── package.json
├── tsconfig.json
├── vite.config.ts
├── tailwind.config.js
├── components.json        # shadcn/ui manifest
└── README.md
```

## Things on disk

`%APPDATA%\packet-eye\packet-eye\config\alert-rules.json`
: Persisted alert rules.

`%APPDATA%\packet-eye\packet-eye\data\geoip\`
: Override location for runtime-updated `.mmdb` files.

`localStorage` (browser side)
: Panel positions, column widths, sort state, sound preferences.
