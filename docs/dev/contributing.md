# Contributing

Thanks for taking a look. The repo is small, opinionated, and the
codebase has been kept simple so anyone reading the source can follow
along — please keep that vibe.

## Local setup

See [Installation](../guide/install.md) and
[Running the app](../guide/running.md).

## Build commands

| Command | What |
|---|---|
| `npm run dev` | Vite dev server with HMR. |
| `npm run build` | TypeScript check + Vite production build into `dist/`. |
| `npm run lint` | TypeScript check only (no Vite). |
| `npm run agent:check` | `cargo check` on the agent. |
| `npm run agent:build` | `cargo build --release` on the agent. |
| `npm run agent:run` | `cargo run` on the agent (must be Administrator). |
| `npm run fetch-geoip` | Re-download the GeoLite2 City + ASN files. |

The `agent:*` commands shell out to a small `scripts/cargo.ps1`
wrapper so they work even right after a fresh Rust install before
you've restarted your terminal.

## Coding style

### Rust

- Follow the formatting `rustfmt --edition=2021` produces — no manual
  alignment.
- Prefer small `mod`s over giant files. `state.rs`, `enrich/`, etc.
  each own one concern.
- Keep handlers in `agent/src/api/` thin: extract heavy work into
  `enrich`, `alerts`, etc.
- New crate dependencies should justify themselves — we already have
  axum, tokio, serde, parking_lot, etc.

### TypeScript

- React function components only, no class components.
- One Zustand store per concern — don't aggregate everything into a
  god store.
- Keep heavy `@react-three/*` imports inside `src/scene/*` so they
  stay in the lazy chunk.
- shadcn/ui primitives live under `src/components/ui/` and are vendored
  (copy-pasted, not installed). When you bring in a new one,
  `components.json` is the manifest.

## Adding an alert rule

1. Open `agent/src/alerts/rules.rs` and add the boolean field to
   `AlertRules` plus a sensible default.
2. Open `agent/src/alerts/engine.rs` and add the evaluation block in
   `evaluate()`. Each block should:
   - check the toggle,
   - filter out non-routable IPs (helper `is_routable_public`
     already does this once at the top, so private IPs are
     automatically excluded — keep it that way),
   - emit one or zero `Alert` per packet,
   - debounce its own retriggers with a per-IP `last_alert_at` if
     the rule can otherwise fire continuously.
3. Mirror the new field in `src/lib/types.ts → AlertRules` and the
   editor section in `src/panels/Preferences.tsx`.

## Pull requests

- Branch off `main`, push to your fork, open a PR.
- Keep PRs scoped: one feature or fix at a time.
- Run `npm run build` and `npm run agent:check` before pushing.
- Doc changes in `docs/` are very welcome — the site is built straight
  from there.
