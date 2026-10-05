# History

Everything the agent captures is also written to a local SQLite
database, so you can look back at what happened while you weren't
watching.

## What is stored

Not individual packets: traffic is aggregated **per minute and per
flow** (protocol, local and remote endpoint) with the packet and byte
counts, the owning process, the domain, and the GeoIP / ASN data. The
database therefore grows with the number of distinct connections, not
with the packet rate. Alerts are stored too.

File: `%APPDATA%\packet-eye\packet-eye\data\history.sqlite`. Data is
flushed every 10 seconds.

## The History tab

- **Period** — 1 h to 30 d presets. The timeline shows bytes per bucket
  (1 minute to 1 day depending on the period); **click a bar to zoom**
  into that slot, *Reset zoom* to go back.
- **Search** — filters the connections table by IP, domain, process,
  ASN organisation, country or city.
- **Top connections** — remote endpoints sorted by bytes over the
  period, with first/last seen, and a block button per row.
- **Alerts** — every alert raised during the period.

## Settings

The ⚙ button opens the history settings:

- **Record history** — turn recording on/off (the live view keeps
  working either way).
- **Keep** — retention, 1 to 90 days (default 7). Older rows are purged
  hourly and right after you change the setting.
- **Clear history** — deletes everything and compacts the file.

Settings are stored in
`%APPDATA%\packet-eye\packet-eye\config\history.json`.
