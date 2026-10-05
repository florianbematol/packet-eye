# Frontend layout

```text
src/
├── main.tsx               React entry, mounts <App>
├── App.tsx                Top-level layout, WebSocket wiring
├── styles/globals.css     Tailwind base + neon palette + glass utilities
├── vite-env.d.ts          Ambient types for VITE_AGENT_URL etc.
│
├── components/
│   ├── DraggablePanel.tsx       Generic panel that can be moved by the user
│   ├── ResizableRightPanel.tsx  Right-edge panel with horizontal resize handle
│   ├── HexDump.tsx              Wireshark-style hex dump renderer
│   ├── BlockButton.tsx          "Block IP / app" button + confirmation dialog
│   ├── ViewShell.tsx            Container + segmented control for the views
│   └── ui/                      shadcn/ui primitives (button, card, dialog, …)
│
├── lib/
│   ├── api.ts             Typed REST client, agent detection, .pcapng download
│   ├── ws.ts              Auto-reconnecting WebSocket
│   ├── types.ts           Shared types (mirrors the Rust models)
│   ├── audio.ts           Web Audio synthesizer for alert tones
│   ├── bpf.ts             Mirror of the Rust BPF builder for live preview
│   ├── geo.ts             latLonToVec3 + Bezier arc builder
│   ├── format.ts          formatBps / formatBytes / formatNumber
│   ├── range.ts           Time-range presets + timeline bucket size
│   ├── useResize.ts       Generic drag-to-resize hook
│   └── utils.ts           shadcn cn(...)
│
├── store/
│   ├── connectionsStore.ts  Live packets + aggregated 5-tuple connections
│   ├── alertsStore.ts       Bounded ring of alerts
│   ├── selectionStore.ts    Currently selected/hovered connection id
│   ├── firewallStore.ts     Packet Eye firewall rules + IP/app matching
│   ├── viewStore.ts         Current top-level view (persisted)
│   └── prefsStore.ts        UI preferences persisted to localStorage
│
├── panels/
│   ├── CapturePanel.tsx           Device picker + filters + start/stop + export
│   ├── StatsBar.tsx               Header throughput counters
│   ├── ConnectionsList.tsx        Sortable, resizable, clickable table
│   ├── AlertsFeed.tsx             Severity-ordered alert list
│   ├── SelectedConnectionPanel.tsx  Details, domain, actions, packets, hex dump
│   └── Preferences.tsx            Tabs: Alert rules / Sounds / GeoIP / Threat lists
│
├── views/                 Lazy-loaded full-screen views (header tabs)
│   ├── AppsView.tsx       Per-application traffic, live or historical
│   ├── HistoryView.tsx    Timeline, top connections, alerts, retention
│   └── FirewallView.tsx   Rule dashboard, manual rules, flagged endpoints
│
└── scene/
    ├── GlobeScene.tsx     react-three-fiber Canvas, Earth + arcs + hotspots
    ├── Earth.tsx          Sphere + textures + Fresnel atmosphere
    ├── Hotspot.tsx        Constant-pixel-size marker
    └── Arc.tsx            Drei <Line> with animated comet head
```

## State propagation

The main `App.tsx` does three things:

1. Subscribes to the agent's WebSocket and routes its three message
   types (`packets`, `stats`, `alerts`) into the Zustand stores.
2. Plays an alert tone for the highest-severity alert in each batch
   and triggers a flash on the corresponding connection
   (`flashRemote(ip, ms)` on `connectionsStore`).
3. Lays out the four overlays:
   - **Capture** (top-left, draggable),
   - **Alerts feed** (bottom-left, draggable),
   - **Selection details** (anywhere, draggable, only when something
     is selected),
   - **Live connections** (right-edge, resizable),
   on top of the **Globe scene** which fills the background.

## Lazy loading

`GlobeScene` and `Preferences` are loaded on demand via
`React.lazy`. The first paint only contains the panels, which weigh
~50 KB gzipped. The 3D engine (Three.js + @react-three/* +
postprocessing) is its own chunk (~290 KB gzipped), loaded once and
cached.

## Theming

Tailwind v3 with shadcn/ui CSS variables. The neon palette extension
adds:

```css
--neon-cyan: 187 100% 55%;
--neon-violet: 271 91% 65%;
--neon-pink: 330 90% 65%;
--neon-green: 145 80% 60%;
--neon-amber: 38 95% 60%;
--neon-red: 350 90% 60%;
```

Used directly in components via `text-neon-cyan`, `bg-neon-violet/20`,
etc.

`.glass` and `.glass-strong` utility classes provide the recurring
backdrop-blur frosted look on every floating panel.
