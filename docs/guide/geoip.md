# GeoIP databases

Packet Eye uses the **MaxMind GeoLite2** databases — `GeoLite2-City`
for country/city/lat/lon and `GeoLite2-ASN` for the autonomous system
number and organisation name.

Both files are sourced from the
[P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) GitHub
mirror, which republishes the latest MaxMind snapshots without
requiring a MaxMind account or licence key. The data itself remains
under the
[GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula).

## Where the files live

The agent looks for the `.mmdb` files in this order:

1. **CLI override** — `--city-db <path>` / `--asn-db <path>`.
2. `<cwd>/resources/<file>`
3. `<cwd>/agent/resources/<file>` (so `cargo run` from the workspace
   root works).
4. `<exe-dir>/resources/<file>`.
5. `<exe-dir>/../../resources/<file>` (cargo's `target/debug` layout).
6. **`%APPDATA%\packet-eye\packet-eye\data\geoip\<file>`** — set by
   the runtime updater. Wins over all of the above when present.

The first match wins. If nothing is found, the resolver runs in empty
mode and every lookup returns `None` — connections then show up
without a country/city/ASN, but capture itself keeps working.

## Initial population

```powershell
npm run fetch-geoip
```

`scripts/fetch-geoip.ps1` downloads the latest mirror release into
`agent/resources/`. It also handles a `-Force` flag to skip the
"younger than 14 days" cache check, and atomic-renames the downloads
to avoid leaving partial files behind.

## Runtime updates

`Preferences ▸ GeoIP` in the gear menu shows you which file is
currently active (path, size, modified date, source) and offers an
**Update now** button. Behind the scenes:

1. The frontend calls `POST /api/geoip/update`.
2. The agent fetches both files from the P3TERX `latest` release tag
   into `%APPDATA%\packet-eye\packet-eye\data\geoip\`.
3. Each file is sanity-checked (City must be ≥ 50 MB, ASN ≥ 5 MB) to
   reject obvious 404 redirects.
4. The download is atomic-renamed.
5. The agent **hot-reloads** both readers (no capture restart). The
   GeoIP cache is cleared so subsequent enrichments use the new data.

A second concurrent update returns 409 (only one updater at a time).

## ETA

A full update takes ~15–25 s on a typical home connection: City is
~63 MB, ASN ~12 MB. The button shows a spinner; you can keep using
the rest of the UI while it runs.
