"""
scanner.py — Background scan job runner for Deep42.

Uses ThreadPoolExecutor with configurable concurrency (CATALOG_SCAN_WORKERS env var).
Each scan job runs in a thread, writes to SQLite via database.py.
"""

import os
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, Future
from datetime import datetime, timezone
from typing import Dict, Optional

import database as db
from rules_engine import effective_policy

logger = logging.getLogger("deep42.scanner")

MAX_WORKERS = int(os.environ.get("CATALOG_SCAN_WORKERS", "2"))
_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="deep42-scan")
_active_jobs: Dict[str, Future] = {}
_cancel_flags: Dict[str, threading.Event] = {}
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def submit_scan(job_id: str, source_id: str, mode: str) -> None:
    """Submit a scan job to the thread pool."""
    cancel_flag = threading.Event()

    with _lock:
        _cancel_flags[job_id] = cancel_flag
        future = _executor.submit(_run_scan, job_id, source_id, mode, cancel_flag)
        _active_jobs[job_id] = future

    def _on_done(f: Future):
        with _lock:
            _active_jobs.pop(job_id, None)
            _cancel_flags.pop(job_id, None)

    future.add_done_callback(_on_done)


def cancel_scan(job_id: str) -> bool:
    """Request cancellation of a running scan."""
    with _lock:
        flag = _cancel_flags.get(job_id)
        future = _active_jobs.get(job_id)

    if flag:
        flag.set()

    if future and not future.done():
        # Can't interrupt a running thread, but the cancel flag will stop it
        db.update_scan_job(job_id, status="canceled", completed_at=_now())
        return True

    return False


def _run_scan(job_id: str, source_id: str, mode: str, cancel_flag: threading.Event):
    """Main scan worker — runs in a thread."""
    logger.info(f"[{job_id}] Starting {mode} scan for source {source_id}")
    db.update_scan_job(job_id, status="running", started_at=_now())

    try:
        source = db.get_source(source_id)
        if not source:
            raise ValueError(f"Source {source_id} not found")

        if source["type"] == "local_fs":
            _scan_local(job_id, source, cancel_flag)
        elif source["type"] in ("dropbox_user", "dropbox_team"):
            _scan_dropbox(job_id, source, mode, cancel_flag)
        else:
            raise ValueError(f"Unknown source type: {source['type']}")

        if cancel_flag.is_set():
            db.update_scan_job(job_id, status="canceled", completed_at=_now())
        else:
            db.update_scan_job(job_id, status="done", completed_at=_now())
            logger.info(f"[{job_id}] Scan complete")

    except Exception as e:
        logger.error(f"[{job_id}] Scan error: {e}", exc_info=True)
        db.update_scan_job(
            job_id, status="error",
            completed_at=_now(),
            error_message=str(e)[:500]
        )


def _flush_batch(conn, source_id: str, batch: list) -> None:
    """Write a batch of entries to SQLite using executemany — no lock needed,
    caller owns the connection in this thread."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany("""
        INSERT INTO entries (id, source_id, path, name, entry_type,
            extension, mime_type, size, created_at, modified_at,
            dropbox_id, dropbox_rev, dropbox_hash, indexed_at)
        VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_id, path) DO UPDATE SET
            name=excluded.name, entry_type=excluded.entry_type,
            extension=excluded.extension, mime_type=excluded.mime_type,
            size=excluded.size, created_at=excluded.created_at,
            modified_at=excluded.modified_at,
            dropbox_id=excluded.dropbox_id, dropbox_rev=excluded.dropbox_rev,
            dropbox_hash=excluded.dropbox_hash, indexed_at=excluded.indexed_at
    """, [
        (source_id, e["path"], e["name"], e.get("entry_type", "file"),
         e.get("extension"), e.get("mime_type"),
         e.get("size"), e.get("created_at"), e.get("modified_at"),
         e.get("dropbox_id"), e.get("dropbox_rev"), e.get("dropbox_hash"), now)
        for e in batch
    ])
    conn.commit()


def _scan_local(job_id: str, source: dict, cancel_flag: threading.Event):
    from connectors.local_fs import scan_local

    rules = db.list_rules(source["id"])
    default_policy = source.get("default_policy", "include")
    root_path = source["root_path"]

    scanned = included = excluded = 0
    conn = db.get_conn()

    def on_progress(count: int):
        nonlocal scanned
        scanned = count
        db.update_scan_job(job_id, items_scanned=count, items_included=included, items_excluded=excluded)

    def should_cancel() -> bool:
        return cancel_flag.is_set()

    BATCH_SIZE = 500
    batch = []

    for entry in scan_local(root_path, on_progress=on_progress, should_cancel=should_cancel):
        if cancel_flag.is_set():
            break

        scanned += 1
        policy = effective_policy(entry["path"], default_policy, rules)

        if policy == "include":
            included += 1
            batch.append(entry)
        else:
            excluded += 1

        if len(batch) >= BATCH_SIZE:
            _flush_batch(conn, source["id"], batch)
            batch.clear()
            db.update_scan_job(
                job_id,
                items_scanned=scanned,
                items_included=included,
                items_excluded=excluded
            )

    # Flush remaining
    if batch:
        _flush_batch(conn, source["id"], batch)

    db.update_scan_job(
        job_id,
        items_scanned=scanned,
        items_included=included,
        items_excluded=excluded
    )


def _scan_dropbox(job_id: str, source: dict, mode: str, cancel_flag: threading.Event):
    from connectors.dropbox_api import (
        scan_dropbox_full, scan_dropbox_incremental, get_cursor_after_full_scan,
        DROPBOX_AVAILABLE
    )

    if not DROPBOX_AVAILABLE:
        raise RuntimeError("Dropbox SDK not installed. Run: pip install dropbox")

    cred = db.get_credentials(source["credentials_ref"])
    if not cred:
        raise ValueError("No credentials found for this source")

    token_data = cred["token_data"]
    cloud_root = source.get("cloud_root") or ""
    teamspace_enabled = bool(source.get("teamspace_enabled"))
    rules = db.list_rules(source["id"])
    default_policy = source.get("default_policy", "include")

    scanned = included = excluded = 0
    conn = db.get_conn()
    BATCH_SIZE = 500
    batch = []

    def on_progress(count: int):
        db.update_scan_job(job_id, items_scanned=count, items_included=included)

    def should_cancel() -> bool:
        return cancel_flag.is_set()

    final_cursor = None

    if mode == "incremental":
        existing_cursor = db.get_latest_cursor(source["id"])
        if not existing_cursor:
            logger.info(f"[{job_id}] No cursor found, falling back to full scan")
            mode = "manual"

    if mode == "incremental":
        gen = scan_dropbox_incremental(
            token_data, existing_cursor, teamspace_enabled,
            on_progress=on_progress, should_cancel=should_cancel
        )
    else:
        gen = scan_dropbox_full(
            token_data, cloud_root, teamspace_enabled,
            on_progress=on_progress, should_cancel=should_cancel
        )

    for entry in gen:
        if cancel_flag.is_set():
            break

        scanned += 1

        # Handle deletions from incremental scan
        if entry.get("entry_type") == "deleted":
            with db._lock:
                conn.execute(
                    "DELETE FROM entries WHERE source_id = ? AND path = ?",
                    (source["id"], entry["path"])
                )
            continue

        policy = effective_policy(entry["path"], default_policy, rules)
        if policy == "include":
            included += 1
            batch.append(entry)
        else:
            excluded += 1

        if len(batch) >= BATCH_SIZE:
            _flush_batch(conn, source["id"], batch)
            batch.clear()
            db.update_scan_job(
                job_id,
                items_scanned=scanned,
                items_included=included,
                items_excluded=excluded
            )

    # Flush remaining
    if batch:
        _flush_batch(conn, source["id"], batch)

    # Persist cursor for next incremental scan
    final_cursor = getattr(gen, "_cursor", None)
    db.update_scan_job(
        job_id,
        items_scanned=scanned,
        items_included=included,
        items_excluded=excluded,
        cursor_data=final_cursor
    )
