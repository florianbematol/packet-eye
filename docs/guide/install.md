# Installation

Packet Eye targets **Windows 10/11** today. macOS and Linux ports are
possible (libpcap exists everywhere) but untested.

## Prerequisites

You need:

1. **Visual Studio 2022 Build Tools** with the *Desktop development
   with C++* workload (this gives you MSVC + the Windows SDK that the
   Rust toolchain needs).
2. **Rust stable**, `x86_64-pc-windows-msvc` host:
   ```powershell
   rustup default stable-x86_64-pc-windows-msvc
   ```
3. **Node.js 18+** with `npm`.
4. **Npcap runtime** — install from
   [npcap.com](https://npcap.com/dist/npcap-1.79.exe). When the
   installer asks, leave *WinPcap API-compatible Mode* checked. If you
   want to capture loopback (`127.0.0.1`) traffic, also check the
   *Npcap Loopback Adapter* option.
5. **Npcap SDK** extracted to `C:\npcap-sdk` — needed only at build
   time. Download:
   [npcap.com/#download](https://npcap.com/#download). The path is
   hard-coded in `.cargo/config.toml`; adjust it there if you put the
   SDK elsewhere.

## Cloning

```powershell
git clone https://github.com/florianbematol/packet-eye.git
cd packet-eye
```

## Frontend dependencies

```powershell
npm install
```

About 270 packages, takes ~30 seconds on a clean disk.

## GeoIP databases

The agent needs two MaxMind GeoLite2 files (City + ASN). They're not
checked into the repo because they're big (~75 MB) and they update
weekly.

```powershell
npm run fetch-geoip
```

This script downloads the latest snapshots from the
[P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) GitHub
mirror straight into `agent/resources/`. No MaxMind account needed.

You can also refresh them later from the UI — see
[GeoIP databases](geoip.md).

## Building the agent

```powershell
npm run agent:build      # release
# or
npm run agent:check      # type-check only
```

This wraps `cargo build --release --manifest-path agent/Cargo.toml`,
prefixing your PATH with `~/.cargo/bin` so it works even if Rust isn't
on your PATH yet.

The release binary lands in `agent/target/release/packet-eye-agent.exe`
(~12 MB).

## Threat lists

The IP block lists used by the alert engine are **not** stored in the
repository (their licences don't all allow redistribution). Download
them once:

```powershell
npm run fetch-threats
```

This writes into `agent/resources/threat-lists/`:

- `spamhaus-drop.txt` — [Spamhaus DROP](https://www.spamhaus.org/drop/)
- `firehol-level1.netset` — [FireHOL Level 1](https://iplists.firehol.org/)
- `tor-exit.txt` — [Tor exit addresses](https://check.torproject.org/exit-addresses)
- `custom.txt` — created empty if missing; add your own IPs / CIDRs

Re-run the same command whenever you want fresher lists, then restart
the agent. Without the lists the agent still runs, the `threat-list`
alert rule simply never fires.

You're now ready to [run the app](running.md).
