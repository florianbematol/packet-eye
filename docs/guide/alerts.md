# Alerts & threat lists

The agent runs every enriched packet through an **alert engine**. Each
rule is a yes/no check that can fire an alert with a severity, a short
message, and the offending remote IP.

Alerts are pushed to the browser via the same WebSocket that streams
packets, so they arrive within a few hundred milliseconds.

## Where they show up

- **Alerts feed** (bottom-left panel) — chronological list, newest
  first. Each row is colour-coded by severity, click ✕ to dismiss
  individual alerts or the trash icon to clear all.
- **Globe** — the offending hotspot pulses red for a few seconds.
- **Connections table** — the matching row gets a red tint until the
  flash expires.
- **Sound** — optional; the matching tone plays through the Web Audio
  API. See *Sounds* below.

## Built-in rules

| Rule | Severity | Default | What it checks |
|---|---|---|---|
| `threat-list` | critical | on | Remote IP belongs to one of the bundled lists (Spamhaus DROP, FireHOL Level 1, Tor exit node, your `custom.txt`). |
| `burst` | high | on | More than `burst_threshold_pps` packets per second toward the same remote IP. Default threshold: 500 pps. |
| `suspicious-port` | medium | on | Outbound connection to a port that's commonly malicious — Telnet (23), SMB (445), 1337, RDP (3389), 4444, 5555, 6666, IRC (6667), 31337. |
| `new-process-external` | low | off | A process you've never seen reach out before is now talking to a public IP. Useful for spotting backdoors that just woke up. |
| `new-asn` | info | off | First time the user contacts a given ASN. Generates a few alerts at startup, then quiets down. |
| `new-country` | info | on | First time the user contacts a given country. Useful for travel/anomaly detection. |

Private / loopback / multicast / link-local addresses **never** trigger
alerts, even if they happen to be inside a third-party block list — too
many false positives (FireHOL L1 famously contains `192.168.0.0/16`).

## Configuration

`Preferences ▸ Alert rules` in the gear menu (top-right of the header).

You can:

- Toggle the **master switch** off (silences everything).
- Toggle each rule individually.
- Edit the burst threshold.

Settings are persisted server-side at
`%APPDATA%\packet-eye\packet-eye\config\alert-rules.json` so they
survive across runs and are shared with any browser instance pointing
at the same agent.

## Threat list maintenance

The lists aren't shipped with the repository. Download or refresh them
with:

```powershell
npm run fetch-threats
```

This pulls Spamhaus DROP, FireHOL Level 1 and the Tor exit addresses
into `agent/resources/threat-lists/` (your `custom.txt` is left
untouched). Then restart the agent. A built-in updater à la GeoIP is on
the roadmap.

## Sounds

`Preferences ▸ Sounds`:

- Master switch (default: on).
- Volume slider (0–100%).
- Per-severity toggle (default: critical/high/medium on, low/info off).
- *Test* buttons that play each tone right away.

Sounds are **synthesised in the browser** via Web Audio (square /
sawtooth / triangle / sine oscillators with ADSR envelopes) — no audio
files shipped, no autoplay quirks. Each severity has a distinct
frequency / sweep so you recognise it without looking. Sounds for the
same severity are **debounced 1.5 s** so a flood doesn't drown you.

The audio context is unlocked on the first click anywhere on the page
(browsers require a user gesture).
