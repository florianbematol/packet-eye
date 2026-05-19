# Releasing

There's no automated release pipeline yet. The intended flow is:

1. Bump the version in `package.json` and `agent/Cargo.toml` together.
2. Run a clean build:
   ```powershell
   npm run build
   npm run agent:build
   ```
3. Tag the commit:
   ```powershell
   git tag -a v0.x.0 -m "Packet Eye v0.x.0"
   git push --tags
   ```
4. Create a GitHub release manually, attach
   `agent/target/release/packet-eye-agent.exe` and the `dist/` SPA
   tarball.

## Documentation site

The MkDocs site is built and deployed automatically by the
`.github/workflows/docs.yml` workflow on every push to `main`. The
deploy target is GitHub Pages (`gh-pages` branch).

To preview locally:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docs/requirements.txt
mkdocs serve
```

Then open `http://127.0.0.1:8000`.
