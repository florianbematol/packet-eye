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

The lists aren't shipped with the repository. Refresh them from the UI
in **Preferences ▸ Threat lists ▸ Update lists now**: the agent
downloads Spamhaus DROP, FireHOL Level 1 and the Tor exit addresses and
reloads them in place — no restart. The tab also shows each list's
entry count and last update. A list that fails to download keeps its
previous version.

For a first install (or from a script), the same download is available
as:

```powershell
npm run fetch-threats
```

Your own `custom.txt` (one IP or CIDR per line) is never overwritten;
use *Update lists now* after editing it to reload it.

Every alert is also saved in the [history](history.md), and the
[Firewall](firewall.md) tab lists the endpoints flagged during the
session with a one-click *Block*.

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
