"""
database.py — Deep42 SQLite catalog layer.
Single-connection, WAL mode, thread-safe via lock.
"""

import sqlite3
import threading
import uuid
import json
import socket
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

DB_PATH = Path(os.environ.get("DEEP42_DB_PATH", "deep42_catalog.db"))
_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def get_conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.execute("PRAGMA foreign_keys=ON")
            _conn.execute("PRAGMA synchronous=NORMAL")
            _init_schema(_conn)
            _conn.commit()
            _ensure_machine(_conn)
            _conn.commit()
    return _conn


def _init_schema(conn: sqlite3.Connection):
    # Step 1 — create tables (IF NOT EXISTS, safe on existing DBs)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS machines (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            token_data TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sources (
            id TEXT PRIMARY KEY,
            machine_id TEXT,
            type TEXT NOT NULL,
            root_path TEXT,
            cloud_root TEXT,
            credentials_ref TEXT,
            default_policy TEXT NOT NULL DEFAULT 'include',
            enabled INTEGER NOT NULL DEFAULT 1,
            teamspace_enabled INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            display_name TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            path_prefix TEXT NOT NULL,
            policy TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS entries (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            path TEXT NOT NULL,
            name TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            extension TEXT,
            mime_type TEXT,
            size INTEGER,
            created_at TEXT,
            modified_at TEXT,
            dropbox_id TEXT,
            dropbox_rev TEXT,
            dropbox_hash TEXT,
            indexed_at TEXT DEFAULT (datetime('now')),
            UNIQUE(source_id, path),
            FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scan_jobs (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'manual',
            status TEXT NOT NULL DEFAULT 'queued',
            started_at TEXT,
            completed_at TEXT,
            items_scanned INTEGER DEFAULT 0,
            items_included INTEGER DEFAULT 0,
            items_excluded INTEGER DEFAULT 0,
            error_message TEXT,
            cursor_data TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (source_id) REFERENCES sources(id)
        );
    """)

    # Step 2 — migrate columns BEFORE creating indexes that reference them
    # (existing DBs won't have extension/mime_type/created_at yet)
    _migrate_entries_columns(conn)

    # Step 3 — create indexes (now safe — columns guaranteed to exist)
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_entries_source    ON entries(source_id);
        CREATE INDEX IF NOT EXISTS idx_entries_path      ON entries(path);
        CREATE INDEX IF NOT EXISTS idx_entries_name      ON entries(name COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_entries_extension ON entries(extension);
        CREATE INDEX IF NOT EXISTS idx_rules_source      ON rules(source_id);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_source  ON scan_jobs(source_id);
        CREATE INDEX IF NOT EXISTS idx_scan_jobs_status  ON scan_jobs(status);
    """)


def _migrate_entries_columns(conn: sqlite3.Connection):
    """Idempotent: add columns that may not exist in databases created before this version."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(entries)").fetchall()}
    migrations = [
        ("extension",  "ALTER TABLE entries ADD COLUMN extension  TEXT"),
        ("mime_type",  "ALTER TABLE entries ADD COLUMN mime_type  TEXT"),
        ("created_at", "ALTER TABLE entries ADD COLUMN created_at TEXT"),
    ]
    for col, sql in migrations:
        if col not in existing:
            conn.execute(sql)


def _ensure_machine(conn: sqlite3.Connection):
    row = conn.execute("SELECT id FROM machines LIMIT 1").fetchone()
    if not row:
        conn.execute(
            "INSERT INTO machines (id, hostname) VALUES (?, ?)",
            (_new_id(), socket.gethostname())
        )


# ─── Machine ─────────────────────────────────────────────────────────────────

def get_machine() -> Optional[Dict]:
    conn = get_conn()
    with _lock:
        row = conn.execute("SELECT * FROM machines LIMIT 1").fetchone()
        return dict(row) if row else None


# ─── Credentials ─────────────────────────────────────────────────────────────

def upsert_credentials(provider: str, token_data: dict) -> str:
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT id FROM credentials WHERE provider = ?", (provider,)
        ).fetchone()
        if row:
            cred_id = row["id"]
            conn.execute(
                "UPDATE credentials SET token_data = ? WHERE id = ?",
                (json.dumps(token_data), cred_id)
            )
        else:
            cred_id = _new_id()
            conn.execute(
                "INSERT INTO credentials (id, provider, token_data) VALUES (?, ?, ?)",
                (cred_id, provider, json.dumps(token_data))
            )
        conn.commit()
        return cred_id


def get_credentials(cred_id: str) -> Optional[Dict]:
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT * FROM credentials WHERE id = ?", (cred_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["token_data"] = json.loads(d["token_data"])
        return d


def list_credentials() -> List[Dict]:
    conn = get_conn()
    with _lock:
        rows = conn.execute("SELECT id, provider, created_at FROM credentials").fetchall()
        return [dict(r) for r in rows]


# ─── Sources ─────────────────────────────────────────────────────────────────

def create_source(data: dict) -> Dict:
    conn = get_conn()
    machine = get_machine()
    sid = _new_id()
    now = _now()
    with _lock:
        conn.execute("""
            INSERT INTO sources (id, machine_id, type, root_path, cloud_root,
                credentials_ref, default_policy, enabled, teamspace_enabled,
                notes, display_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sid,
            machine["id"] if machine else None,
            data["type"],
            data.get("root_path"),
            data.get("cloud_root"),
            data.get("credentials_ref"),
            data.get("default_policy", "include"),
            1 if data.get("enabled", True) else 0,
            1 if data.get("teamspace_enabled", False) else 0,
            data.get("notes"),
            data.get("display_name"),
            now, now
        ))
        conn.commit()
    return get_source(sid)


def get_source(source_id: str) -> Optional[Dict]:
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT * FROM sources WHERE id = ?", (source_id,)
        ).fetchone()
        return dict(row) if row else None


def list_sources() -> List[Dict]:
    conn = get_conn()
    with _lock:
        rows = conn.execute(
            "SELECT * FROM sources ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_source(source_id: str) -> bool:
    conn = get_conn()
    with _lock:
        cur = conn.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        conn.commit()
        return cur.rowcount > 0


# ─── Rules ───────────────────────────────────────────────────────────────────

def create_rule(source_id: str, path_prefix: str, policy: str) -> Dict:
    conn = get_conn()
    rid = _new_id()
    with _lock:
        conn.execute(
            "INSERT INTO rules (id, source_id, path_prefix, policy) VALUES (?, ?, ?, ?)",
            (rid, source_id, path_prefix, policy)
        )
        conn.commit()
    return {"id": rid, "source_id": source_id, "path_prefix": path_prefix, "policy": policy}


def list_rules(source_id: str) -> List[Dict]:
    conn = get_conn()
    with _lock:
        rows = conn.execute(
            "SELECT * FROM rules WHERE source_id = ? ORDER BY length(path_prefix) DESC",
            (source_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def delete_rule(rule_id: str) -> bool:
    conn = get_conn()
    with _lock:
        cur = conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        conn.commit()
        return cur.rowcount > 0


# ─── Entries ─────────────────────────────────────────────────────────────────

def upsert_entry(source_id: str, entry: dict) -> None:
    conn = get_conn()
    with _lock:
        conn.execute("""
            INSERT INTO entries (id, source_id, path, name, entry_type,
                extension, mime_type, size, created_at, modified_at,
                dropbox_id, dropbox_rev, dropbox_hash, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id, path) DO UPDATE SET
                name        = excluded.name,
                entry_type  = excluded.entry_type,
                extension   = excluded.extension,
                mime_type   = excluded.mime_type,
                size        = excluded.size,
                created_at  = excluded.created_at,
                modified_at = excluded.modified_at,
                dropbox_id  = excluded.dropbox_id,
                dropbox_rev = excluded.dropbox_rev,
                dropbox_hash= excluded.dropbox_hash,
                indexed_at  = excluded.indexed_at
        """, (
            _new_id(),
            source_id,
            entry["path"],
            entry["name"],
            entry.get("entry_type", "file"),
            entry.get("extension"),
            entry.get("mime_type"),
            entry.get("size"),
            entry.get("created_at"),
            entry.get("modified_at"),
            entry.get("dropbox_id"),
            entry.get("dropbox_rev"),
            entry.get("dropbox_hash"),
            _now()
        ))


def flush_entries(conn: sqlite3.Connection):
    conn.commit()


def search_entries(q: str, source_id: Optional[str] = None, limit: int = 50) -> List[Dict]:
    conn = get_conn()
    like = f"%{q}%"
    with _lock:
        if source_id:
            rows = conn.execute("""
                SELECT e.*, s.type as source_type, s.display_name as source_name
                FROM entries e
                JOIN sources s ON e.source_id = s.id
                WHERE e.source_id = ? AND e.name LIKE ? COLLATE NOCASE
                ORDER BY e.name LIMIT ?
            """, (source_id, like, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT e.*, s.type as source_type, s.display_name as source_name
                FROM entries e
                JOIN sources s ON e.source_id = s.id
                WHERE e.name LIKE ? COLLATE NOCASE
                ORDER BY e.name LIMIT ?
            """, (like, limit)).fetchall()
        return [dict(r) for r in rows]


def browse_entries(source_id: str, parent_path: str) -> List[Dict]:
    conn = get_conn()
    # Normalize: add trailing slash for prefix matching
    prefix = parent_path.rstrip("/") + "/"
    if parent_path in ("", "/"):
        prefix = "/"

    with _lock:
        # Direct children only: path starts with prefix and has no more slashes after
        rows = conn.execute("""
            SELECT * FROM entries
            WHERE source_id = ?
              AND (
                path LIKE ? ESCAPE '\\'
                AND path NOT LIKE ? ESCAPE '\\'
              )
            ORDER BY entry_type DESC, name COLLATE NOCASE
        """, (
            source_id,
            prefix + "%",
            prefix + "%/%"
        )).fetchall()
        return [dict(r) for r in rows]


def get_entry_count(source_id: str) -> Dict:
    conn = get_conn()
    with _lock:
        row = conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN entry_type='file' THEN 1 ELSE 0 END) as files,
                SUM(CASE WHEN entry_type='folder' THEN 1 ELSE 0 END) as folders,
                SUM(size) as total_bytes
            FROM entries WHERE source_id = ?
        """, (source_id,)).fetchone()
        return dict(row) if row else {}


# ─── Scan Jobs ───────────────────────────────────────────────────────────────

def create_scan_job(source_id: str, mode: str = "manual") -> Dict:
    conn = get_conn()
    jid = _new_id()
    now = _now()
    with _lock:
        conn.execute("""
            INSERT INTO scan_jobs (id, source_id, mode, status, created_at)
            VALUES (?, ?, ?, 'queued', ?)
        """, (jid, source_id, mode, now))
        conn.commit()
    return get_scan_job(jid)


def get_scan_job(job_id: str) -> Optional[Dict]:
    conn = get_conn()
    with _lock:
        row = conn.execute(
            "SELECT * FROM scan_jobs WHERE id = ?", (job_id,)
        ).fetchone()
        return dict(row) if row else None


def list_scan_jobs(source_id: Optional[str] = None, limit: int = 20) -> List[Dict]:
    conn = get_conn()
    with _lock:
        if source_id:
            rows = conn.execute(
                "SELECT * FROM scan_jobs WHERE source_id = ? ORDER BY created_at DESC LIMIT ?",
                (source_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def update_scan_job(job_id: str, **kwargs) -> None:
    conn = get_conn()
    allowed = {"status", "started_at", "completed_at", "items_scanned",
                "items_included", "items_excluded", "error_message", "cursor_data"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    vals = list(fields.values()) + [job_id]
    with _lock:
        conn.execute(f"UPDATE scan_jobs SET {set_clause} WHERE id = ?", vals)
        conn.commit()


def get_latest_cursor(source_id: str) -> Optional[str]:
    """Get the Dropbox cursor from the last completed scan for incremental mode."""
    conn = get_conn()
    with _lock:
        row = conn.execute("""
            SELECT cursor_data FROM scan_jobs
            WHERE source_id = ? AND status = 'done' AND cursor_data IS NOT NULL
            ORDER BY completed_at DESC LIMIT 1
        """, (source_id,)).fetchone()
        return row["cursor_data"] if row else None
