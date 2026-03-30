# Deep42 — Local Universe Catalog

**Find anything. Move nothing.**

Deep42 builds a searchable metadata catalog of your local folders and Dropbox portals — without reorganizing, uploading, or moving your files.

**Repository:** [github.com/neetasandeepshah/deep42](https://github.com/neetasandeepshah/deep42)

**Maintainer:** GitHub [@neetasandeepshah](https://github.com/neetasandeepshah) · [neetasandeepshah@gmail.com](mailto:neetasandeepshah@gmail.com)

---

## Quick Start

```bash
cd deep42
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Open: http://localhost:8787

---

## Environment Variables

Create a `.env` file or export these before running:

```env
# Required for Dropbox portals (optional for local-only use)
DROPBOX_APP_KEY=your_app_key
DROPBOX_APP_SECRET=your_app_secret
DROPBOX_REDIRECT_URI=http://localhost:8787/api/auth/dropbox/callback

# Optional tuning
CATALOG_SCAN_WORKERS=2          # Concurrent scan threads (default: 2)
DEEP42_DB_PATH=deep42_catalog.db
DEEP42_HOST=127.0.0.1           # Never expose to 0.0.0.0 unless behind Tailscale
DEEP42_PORT=8787
```

### Setting up a Dropbox App

1. Go to https://www.dropbox.com/developers/apps
2. Create a new app → "Scoped access" → "Full Dropbox"
3. Set redirect URI: `http://localhost:8787/api/auth/dropbox/callback`
4. Copy App Key + App Secret → set in env

---

## Remote Access (BYO Tailscale)

Deep42 binds to `127.0.0.1` only. For secure remote access from your phone or other machines:

```bash
# Install Tailscale, sign in, then:
tailscale serve http 8787
```

Access via your Tailscale MagicDNS hostname (e.g. `https://my-mac.tailnet-name.ts.net`).

No port-forwarding. No public exposure. Private to your tailnet only.

---

## Workflow

1. **Sources** — Add local folders or connect Dropbox (Portals tab first)
2. **Rules** — Set include/exclude overrides for specific path prefixes
3. **Scan** — Run a full or incremental scan (configurable concurrency)
4. **Search** — Query your catalog by filename
5. **Browse** — Explore the tree with live policy indicators

---

## Architecture

```
deep42/
├── main.py          — FastAPI app, all API routes
├── database.py      — SQLite WAL catalog layer
├── models.py        — Pydantic request/response schemas
├── rules_engine.py  — Effective policy computation
├── scanner.py       — ThreadPoolExecutor scan worker pool
├── connectors/
│   ├── local_fs.py      — Local filesystem scanner
│   └── dropbox_api.py   — Dropbox API connector (full + incremental)
├── ui/
│   └── index.html   — Full web UI (zero dependencies)
└── requirements.txt
```

---

## API Reference

```
GET    /api/health
GET    /api/sources
POST   /api/sources
DELETE /api/sources/{id}
GET    /api/rules?source_id=...
POST   /api/rules
DELETE /api/rules/{id}
GET    /api/browse?source_id=...&path=...
GET    /api/portal/browse?source_id=...&path=...
GET    /api/search?q=...&source_id=optional
POST   /api/scan/run?source_id=...&mode=manual|incremental
GET    /api/scan/status/{job_id}
POST   /api/scan/cancel/{job_id}
GET    /api/scan/jobs
GET    /api/auth/dropbox/start?account_type=personal|business
GET    /api/auth/dropbox/callback   (OAuth redirect)
GET    /api/auth/dropbox/status
```

Interactive docs at: http://localhost:8787/docs

---

## Phase 2 Roadmap

- Content extraction (PDF / text / markdown / code)
- On-demand embeddings + RAG search
- Google Drive / OneDrive connectors
- Airlock export flow
- macOS Keychain / Windows Credential Manager token storage
