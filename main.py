"""
main.py — Deep42 FastAPI application.

Serves:
  - REST API at /api/...
  - Static Web UI at / (from ui/ directory)
  - Dropbox OAuth callback at /api/auth/dropbox/callback

Bind: 127.0.0.1:8787 (localhost only, BYO Tailscale for remote access)
"""

import os
import logging
from pathlib import Path

# Load .env file if present (must happen before any os.environ.get calls)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

import database as db
import scanner
from chat_api import router as chat_router
from models import (
    SourceCreate, SourceOut,
    RuleCreate, RuleOut,
    ScanJobOut, BrowseItem, SearchResult, SourceStats
)
from rules_engine import effective_policy

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")
logger = logging.getLogger("deep42.api")

app = FastAPI(
    title="Deep42",
    description="Local-first metadata catalog — find anything, move nothing.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8787", "http://127.0.0.1:8787"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chat_router)

# ─── Startup ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
def on_startup():
    db.get_conn()  # Initialize DB + schema
    logger.info("Deep42 started. DB at: %s", db.DB_PATH)
    logger.info("Listening on http://127.0.0.1:8787")
    logger.info("Scan workers: %s", os.environ.get("CATALOG_SCAN_WORKERS", "2"))


# ─── Health ──────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    machine = db.get_machine()
    return {
        "status": "ok",
        "machine": machine.get("hostname") if machine else "unknown",
        "db": str(db.DB_PATH),
        "scan_workers": int(os.environ.get("CATALOG_SCAN_WORKERS", "2")),
    }


# ─── Credentials ─────────────────────────────────────────────────────────────

@app.get("/api/credentials")
def list_creds():
    return db.list_credentials()


# ─── Sources ─────────────────────────────────────────────────────────────────

@app.post("/api/sources", response_model=SourceOut)
def create_source(body: SourceCreate):
    if body.type == "local_fs":
        if not body.root_path:
            raise HTTPException(400, "root_path is required for local_fs sources")
        root = Path(body.root_path).resolve()
        if not root.exists():
            raise HTTPException(400, f"Path does not exist: {root}")
        body.root_path = str(root)
        if not body.display_name:
            body.display_name = root.name

    elif body.type in ("dropbox_user", "dropbox_team"):
        if not body.credentials_ref:
            raise HTTPException(400, "credentials_ref is required for Dropbox sources")
        cred = db.get_credentials(body.credentials_ref)
        if not cred:
            raise HTTPException(400, "credentials_ref not found")
        if not body.display_name:
            body.display_name = f"Dropbox {'Business' if body.type == 'dropbox_team' else 'Personal'}"

    source = db.create_source(body.model_dump())
    return _source_out(source)


@app.get("/api/sources")
def list_sources():
    sources = db.list_sources()
    result = []
    for s in sources:
        out = _source_out(s)
        stats = db.get_entry_count(s["id"])
        out_dict = out.model_dump()
        out_dict["stats"] = {
            "total": stats.get("total") or 0,
            "files": stats.get("files") or 0,
            "folders": stats.get("folders") or 0,
            "total_bytes": stats.get("total_bytes"),
        }
        result.append(out_dict)
    return result


@app.get("/api/sources/{source_id}", response_model=SourceOut)
def get_source(source_id: str):
    source = db.get_source(source_id)
    if not source:
        raise HTTPException(404, "Source not found")
    return _source_out(source)


@app.delete("/api/sources/{source_id}")
def delete_source(source_id: str):
    ok = db.delete_source(source_id)
    if not ok:
        raise HTTPException(404, "Source not found")
    return {"deleted": source_id}


def _source_out(s: dict) -> SourceOut:
    return SourceOut(
        id=s["id"],
        type=s["type"],
        display_name=s.get("display_name"),
        root_path=s.get("root_path"),
        cloud_root=s.get("cloud_root"),
        credentials_ref=s.get("credentials_ref"),
        default_policy=s.get("default_policy", "include"),
        enabled=bool(s.get("enabled", 1)),
        teamspace_enabled=bool(s.get("teamspace_enabled", 0)),
        notes=s.get("notes"),
        created_at=s.get("created_at", ""),
        updated_at=s.get("updated_at", ""),
    )


# ─── Rules ───────────────────────────────────────────────────────────────────

@app.post("/api/rules", response_model=RuleOut)
def create_rule(body: RuleCreate):
    source = db.get_source(body.source_id)
    if not source:
        raise HTTPException(404, "Source not found")
    rule = db.create_rule(body.source_id, body.path_prefix, body.policy)
    return RuleOut(**rule)


@app.get("/api/rules")
def list_rules(source_id: str = Query(...)):
    return db.list_rules(source_id)


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str):
    ok = db.delete_rule(rule_id)
    if not ok:
        raise HTTPException(404, "Rule not found")
    return {"deleted": rule_id}


# ─── Browse ──────────────────────────────────────────────────────────────────

@app.get("/api/browse")
def browse_local(
    source_id: str = Query(...),
    path: str = Query(default="/")
):
    """Browse the catalog (already scanned entries) for a local source."""
    source = db.get_source(source_id)
    if not source:
        raise HTTPException(404, "Source not found")

    rules = db.list_rules(source_id)
    default_policy = source.get("default_policy", "include")

    entries = db.browse_entries(source_id, path)
    result = []
    for e in entries:
        ep = effective_policy(e["path"], default_policy, rules)
        result.append({
            "path": e["path"],
            "name": e["name"],
            "type": e["entry_type"],
            "effective_policy": ep,
            "size": e.get("size"),
            "modified_at": e.get("modified_at"),
        })
    return result


@app.get("/api/portal/browse")
def browse_portal_live(
    source_id: str = Query(...),
    path: str = Query(default="")
):
    """Live browse a Dropbox portal (no scan required)."""
    source = db.get_source(source_id)
    if not source:
        raise HTTPException(404, "Source not found")
    if source["type"] not in ("dropbox_user", "dropbox_team"):
        raise HTTPException(400, "Source is not a portal source")

    cred = db.get_credentials(source["credentials_ref"])
    if not cred:
        raise HTTPException(400, "No credentials for this source")

    try:
        from connectors.dropbox_api import browse_dropbox_live
        entries = list(browse_dropbox_live(
            cred["token_data"],
            path=path or source.get("cloud_root") or "",
            teamspace_enabled=bool(source.get("teamspace_enabled"))
        ))
    except Exception as e:
        raise HTTPException(500, f"Dropbox browse failed: {e}")

    rules = db.list_rules(source_id)
    default_policy = source.get("default_policy", "include")

    result = []
    for e in entries:
        ep = effective_policy(e["path"], default_policy, rules)
        result.append({
            "path": e["path"],
            "name": e["name"],
            "type": e["entry_type"],
            "effective_policy": ep,
            "size": e.get("size"),
            "modified_at": e.get("modified_at"),
        })
    result.sort(key=lambda x: (x["type"] != "folder", x["name"].lower()))
    return result


# ─── Search ──────────────────────────────────────────────────────────────────

@app.get("/api/search")
def search(
    q: str = Query(..., min_length=1),
    source_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=200),
):
    if len(q.strip()) < 1:
        return []
    results = db.search_entries(q.strip(), source_id=source_id, limit=limit)
    return results


# ─── Scan Jobs ───────────────────────────────────────────────────────────────

@app.post("/api/scan/run")
def run_scan(
    source_id: str = Query(...),
    mode: str = Query(default="manual")
):
    if mode not in ("manual", "incremental"):
        raise HTTPException(400, "mode must be 'manual' or 'incremental'")

    source = db.get_source(source_id)
    if not source:
        raise HTTPException(404, "Source not found")
    if not source.get("enabled"):
        raise HTTPException(400, "Source is disabled")

    job = db.create_scan_job(source_id, mode)
    scanner.submit_scan(job["id"], source_id, mode)
    return ScanJobOut(**job)


@app.get("/api/scan/status/{job_id}")
def scan_status(job_id: str):
    job = db.get_scan_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return ScanJobOut(**job)


@app.post("/api/scan/cancel/{job_id}")
def cancel_scan(job_id: str):
    job = db.get_scan_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    ok = scanner.cancel_scan(job_id)
    return {"canceled": ok, "job_id": job_id}


@app.get("/api/scan/jobs")
def list_jobs(
    source_id: Optional[str] = Query(default=None),
    limit: int = Query(default=20)
):
    return db.list_scan_jobs(source_id=source_id, limit=limit)


# ─── Dropbox OAuth ───────────────────────────────────────────────────────────

@app.get("/api/auth/dropbox/start")
def dropbox_auth_start(account_type: str = Query(default="personal")):
    try:
        from connectors.dropbox_api import start_oauth_flow, DropboxConfigError
        auth_url, state = start_oauth_flow(account_type)
        return {"auth_url": auth_url, "state": state}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/api/auth/dropbox/callback")
def dropbox_callback(
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
):
    if error:
        return HTMLResponse(f"""
            <html><body style="font-family:sans-serif;padding:40px;">
            <h2 style="color:#ef4444">Dropbox Authorization Failed</h2>
            <p>{error}</p>
            <script>
                setTimeout(() => {{ window.close(); }}, 3000);
            </script>
            </body></html>
        """)

    if not code or not state:
        raise HTTPException(400, "Missing code or state")

    try:
        from connectors.dropbox_api import complete_oauth_flow
        token_data = complete_oauth_flow(code, state)
        cred_id = db.upsert_credentials(
            f"dropbox_{token_data.get('account_type', 'personal')}",
            token_data
        )
        return HTMLResponse(f"""
            <html><body style="font-family:sans-serif;padding:40px;background:#f0fdf4;">
            <h2 style="color:#16a34a">✓ Dropbox Connected!</h2>
            <p>Credential ID: <code style="background:#dcfce7;padding:4px 8px;border-radius:4px;">{cred_id}</code></p>
            <p>You can close this window and add a source in Deep42.</p>
            <script>
                setTimeout(() => {{
                    window.opener && window.opener.postMessage(
                        {{ type: 'dropbox_auth_complete', cred_id: '{cred_id}' }}, '*'
                    );
                    window.close();
                }}, 1500);
            </script>
            </body></html>
        """)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/api/auth/dropbox/status")
def dropbox_auth_status():
    """Return connected Dropbox accounts."""
    creds = db.list_credentials()
    dbx_creds = [c for c in creds if c["provider"].startswith("dropbox")]
    return {"connected": dbx_creds}


# ─── Dropbox Folder Browser (for cloud root picker UI) ─────────────────────

@app.get("/api/dropbox/browse")
def dropbox_browse(
    cred_id: str = Query(...),
    path: str = Query(default="")
):
    """
    List immediate subfolders of a Dropbox path for the folder-picker modal.
    Returns same shape as /api/fs/browse: {current, parent, dirs}.
    """
    cred = db.get_credentials(cred_id)
    if not cred:
        raise HTTPException(404, "Credential not found")

    try:
        from connectors.dropbox_api import get_dropbox_client
        dbx = get_dropbox_client(cred["token_data"])

        norm = path.rstrip("/") if path and path not in ("/", "") else ""

        result = dbx.files_list_folder(norm, recursive=False, include_deleted=False)
        entries = list(result.entries)
        while result.has_more:
            result = dbx.files_list_folder_continue(result.cursor)
            entries.extend(result.entries)

        from dropbox.files import FolderMetadata
        dirs = sorted(
            [{"name": e.name, "path": e.path_lower} for e in entries if isinstance(e, FolderMetadata)],
            key=lambda x: x["name"].lower()
        )

        # Parent path
        if norm == "":
            parent = None
        else:
            parts = norm.rsplit("/", 1)
            parent = parts[0] if parts[0] else ""

        return {"current": norm or "/", "parent": parent, "dirs": dirs}

    except Exception as e:
        raise HTTPException(500, f"Dropbox browse failed: {e}")


# ─── Local Filesystem Browser (for path picker UI) ──────────────────────────

@app.get("/api/fs/browse")
def fs_browse(path: str = Query(default="~")):
    """
    List immediate subdirectories of `path`.
    Used by the UI folder-picker modal — returns dirs only, no file contents.
    Safe: localhost-only, user's own machine.
    """
    import stat as _stat
    resolved = Path(path.replace("~", str(Path.home()))).resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise HTTPException(400, f"Not a directory: {resolved}")

    dirs = []
    try:
        with os.scandir(resolved) as it:
            for entry in sorted(it, key=lambda e: e.name.lower()):
                if entry.name.startswith("."):
                    continue  # skip hidden
                try:
                    st = entry.stat(follow_symlinks=False)
                    if _stat.S_ISDIR(st.st_mode):
                        dirs.append({"name": entry.name, "path": str(Path(entry.path).resolve())})
                except (PermissionError, OSError):
                    continue
    except PermissionError:
        raise HTTPException(403, f"Permission denied: {resolved}")

    # Parent dir for navigation (None if already at root)
    parent = str(resolved.parent) if resolved.parent != resolved else None

    return {
        "current": str(resolved),
        "parent": parent,
        "dirs": dirs,
    }


# ─── Chat UI ────────────────────────────────────────────────────────────────

@app.get("/chat", response_class=HTMLResponse)
def chat_ui():
    """Serve the mobile AI chat interface (PIN protected, Tailscale only)."""
    chat_html = Path(__file__).parent / "ui" / "chat.html"
    if chat_html.exists():
        return HTMLResponse(chat_html.read_text())
    return HTMLResponse("<h2>chat.html not found — copy it to ui/chat.html</h2>", status_code=404)


# ─── Static UI ───────────────────────────────────────────────────────────────

_ui_dir = Path(__file__).parent / "ui"
if _ui_dir.exists():
    app.mount("/", StaticFiles(directory=str(_ui_dir), html=True), name="ui")
else:
    @app.get("/")
    def root():
        return HTMLResponse("<h1>Deep42</h1><p>Place ui/index.html in the ui/ directory.</p>")


# ─── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("DEEP42_HOST", "127.0.0.1")
    port = int(os.environ.get("DEEP42_PORT", "8787"))

    print(f"""
╔══════════════════════════════════════════╗
║         Deep42 — Local Catalog           ║
║  Find anything. Move nothing.            ║
╠══════════════════════════════════════════╣
║  UI   →  http://{host}:{port}          ║
║  API  →  http://{host}:{port}/api      ║
║  Docs →  http://{host}:{port}/docs     ║
╚══════════════════════════════════════════╝
""")

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )
