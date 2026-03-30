"""
chat_api.py — Deep42 AI Chat endpoint.

Supports two inference backends, selectable via LLM_PROVIDER in .env:
  - "ollama"     (default) — 100% local, zero data leaves the machine
  - "anthropic"  (fallback) — cloud API, requires ANTHROPIC_API_KEY

Ollama setup:
  brew install ollama
  ollama serve
  ollama pull qwen2.5:7b

Security:
  - Bearer token auth (CHAT_TOKEN env var)
  - In-memory rate limiter (60 req / IP / hour, configurable)
  - Read-only Claude tools — no catalog mutations exposed
  - Runs only inside Tailscale network (127.0.0.1 bind)
"""

import os
import json
import time
import logging
import sqlite3
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger("deep42.chat")
router = APIRouter()

# ── Config ────────────────────────────────────────────────────────────────────

# NODE_ROLE: surface (default) — uses configured LLM_PROVIDER for metadata queries
#            vault             — always routes to Ollama, content stays local
NODE_ROLE    = os.environ.get("NODE_ROLE", "surface").lower()
LLM_FALLBACK = os.environ.get("LLM_FALLBACK", "ollama").lower()

def _provider() -> str:
    """Resolve active LLM provider.
    Vault always uses Ollama regardless of LLM_PROVIDER.
    Surface uses whatever LLM_PROVIDER is set to.
    """
    if NODE_ROLE == "vault":
        return "ollama"
    return os.environ.get("LLM_PROVIDER", "ollama").lower()

def _ollama_host()     -> str: return os.environ.get("OLLAMA_HOST", "http://localhost:11434")
def _ollama_model()    -> str:
    # Support both OLLAMA_CHAT_MODEL (new) and OLLAMA_MODEL (legacy)
    return os.environ.get("OLLAMA_CHAT_MODEL") or os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
def _anthropic_key()   -> str: return os.environ.get("ANTHROPIC_API_KEY", "")
def _anthropic_model() -> str: return os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

# ── Rate limiter ──────────────────────────────────────────────────────────────

_rate_store: dict = defaultdict(list)
RATE_LIMIT  = int(os.environ.get("CHAT_RATE_LIMIT", "60"))
RATE_WINDOW = 3600


def _check_rate(ip: str) -> None:
    now = time.time()
    hits = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
    if len(hits) >= RATE_LIMIT:
        raise HTTPException(429, f"Rate limit: {RATE_LIMIT} req/hour")
    hits.append(now)
    _rate_store[ip] = hits


# ── Token auth ────────────────────────────────────────────────────────────────

def _check_token(request: Request) -> None:
    required = os.environ.get("CHAT_TOKEN", "")
    if not required:
        raise HTTPException(500, "CHAT_TOKEN not configured")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    import hmac
    if not hmac.compare_digest(auth[len("Bearer "):].strip(), required):
        raise HTTPException(403, "Invalid token")


# ── DB helpers (read-only SQLite) ─────────────────────────────────────────────

def _db_path() -> str:
    return os.environ.get("DEEP42_DB_PATH", "deep42_catalog.db")

def _db() -> sqlite3.Connection:
    c = sqlite3.connect(_db_path(), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def _search_files(query: str, source_id: Optional[str] = None, limit: int = 20) -> list:
    conn = _db(); like = f"%{query}%"
    try:
        if source_id:
            rows = conn.execute("""
                SELECT e.path, e.name, e.entry_type, e.size, e.modified_at,
                       s.display_name as source_name
                FROM entries e JOIN sources s ON e.source_id = s.id
                WHERE e.source_id=? AND e.name LIKE ? COLLATE NOCASE
                ORDER BY e.name LIMIT ?""", (source_id, like, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT e.path, e.name, e.entry_type, e.size, e.modified_at,
                       s.display_name as source_name
                FROM entries e JOIN sources s ON e.source_id = s.id
                WHERE e.name LIKE ? COLLATE NOCASE
                ORDER BY e.name LIMIT ?""", (like, limit)).fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()

def _get_stats() -> list:
    conn = _db()
    try:
        rows = conn.execute("""
            SELECT s.id, s.display_name, s.type, s.root_path, s.cloud_root,
                   COUNT(e.id) as total_entries,
                   SUM(CASE WHEN e.entry_type='file'   THEN 1 ELSE 0 END) as files,
                   SUM(CASE WHEN e.entry_type='folder' THEN 1 ELSE 0 END) as folders,
                   SUM(e.size) as total_bytes
            FROM sources s LEFT JOIN entries e ON e.source_id=s.id
            WHERE s.enabled=1 GROUP BY s.id ORDER BY files DESC""").fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()

def _browse_folder(source_id: str, path: str = "/", limit: int = 50) -> list:
    conn = _db()
    prefix = (path.rstrip("/") + "/") if path not in ("", "/") else "/"
    try:
        rows = conn.execute("""
            SELECT path, name, entry_type, size, modified_at FROM entries
            WHERE source_id=?
              AND path LIKE ? ESCAPE '\\'
              AND path NOT LIKE ? ESCAPE '\\'
            ORDER BY entry_type DESC, name COLLATE NOCASE LIMIT ?""",
            (source_id, prefix+"%", prefix+"%/%", limit)).fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()

def _find_large_files(source_id: Optional[str] = None, limit: int = 20) -> list:
    conn = _db()
    try:
        if source_id:
            rows = conn.execute("""
                SELECT e.path, e.name, e.size, e.modified_at, s.display_name as source_name
                FROM entries e JOIN sources s ON e.source_id=s.id
                WHERE e.entry_type='file' AND e.source_id=? AND e.size IS NOT NULL
                ORDER BY e.size DESC LIMIT ?""", (source_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT e.path, e.name, e.size, e.modified_at, s.display_name as source_name
                FROM entries e JOIN sources s ON e.source_id=s.id
                WHERE e.entry_type='file' AND e.size IS NOT NULL
                ORDER BY e.size DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()

def _search_by_type(ext_or_mime: str, source_id: Optional[str] = None, limit: int = 30) -> list:
    """Search by extension (e.g. 'pdf') or MIME category (e.g. 'image', 'video')."""
    conn = _db()
    term = ext_or_mime.lower().lstrip('.')
    # Check if it's a MIME category (no slash) or full type
    is_category = '/' not in term and len(term) < 8  # e.g. 'image', 'video', 'audio'
    try:
        if is_category:
            mime_like = f"{term}/%"
            if source_id:
                rows = conn.execute("""
                    SELECT e.path, e.name, e.extension, e.mime_type,
                           e.size, e.created_at, e.modified_at, s.display_name as source_name
                    FROM entries e JOIN sources s ON e.source_id = s.id
                    WHERE e.entry_type='file' AND e.source_id=?
                      AND (e.mime_type LIKE ? OR e.extension=?)
                    ORDER BY e.modified_at DESC LIMIT ?""",
                    (source_id, mime_like, term, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT e.path, e.name, e.extension, e.mime_type,
                           e.size, e.created_at, e.modified_at, s.display_name as source_name
                    FROM entries e JOIN sources s ON e.source_id = s.id
                    WHERE e.entry_type='file'
                      AND (e.mime_type LIKE ? OR e.extension=?)
                    ORDER BY e.modified_at DESC LIMIT ?""",
                    (mime_like, term, limit)).fetchall()
        else:
            if source_id:
                rows = conn.execute("""
                    SELECT e.path, e.name, e.extension, e.mime_type,
                           e.size, e.created_at, e.modified_at, s.display_name as source_name
                    FROM entries e JOIN sources s ON e.source_id = s.id
                    WHERE e.entry_type='file' AND e.source_id=?
                      AND e.extension=?
                    ORDER BY e.modified_at DESC LIMIT ?""",
                    (source_id, term, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT e.path, e.name, e.extension, e.mime_type,
                           e.size, e.created_at, e.modified_at, s.display_name as source_name
                    FROM entries e JOIN sources s ON e.source_id = s.id
                    WHERE e.entry_type='file' AND e.extension=?
                    ORDER BY e.modified_at DESC LIMIT ?""",
                    (term, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _type_breakdown(source_id: Optional[str] = None) -> list:
    """Return count and total size grouped by extension."""
    conn = _db()
    try:
        if source_id:
            rows = conn.execute("""
                SELECT extension, mime_type,
                       COUNT(*) as count,
                       SUM(size) as total_bytes
                FROM entries
                WHERE entry_type='file' AND source_id=?
                  AND extension IS NOT NULL
                GROUP BY extension
                ORDER BY count DESC""", (source_id,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT extension, mime_type,
                       COUNT(*) as count,
                       SUM(size) as total_bytes
                FROM entries
                WHERE entry_type='file' AND extension IS NOT NULL
                GROUP BY extension
                ORDER BY count DESC""").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _find_recent_files(source_id: Optional[str] = None, limit: int = 20) -> list:
    conn = _db()
    try:
        if source_id:
            rows = conn.execute("""
                SELECT e.path, e.name, e.size, e.modified_at, s.display_name as source_name
                FROM entries e JOIN sources s ON e.source_id=s.id
                WHERE e.entry_type='file' AND e.source_id=? AND e.modified_at IS NOT NULL
                ORDER BY e.modified_at DESC LIMIT ?""", (source_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT e.path, e.name, e.size, e.modified_at, s.display_name as source_name
                FROM entries e JOIN sources s ON e.source_id=s.id
                WHERE e.entry_type='file' AND e.modified_at IS NOT NULL
                ORDER BY e.modified_at DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally: conn.close()


# ── Tool execution (shared by both backends) ──────────────────────────────────

def _run_tool(name: str, inputs: dict) -> str:
    try:
        if name == "search_files":
            r = _search_files(inputs["query"], inputs.get("source_id"),
                              min(int(inputs.get("limit", 20)), 50))
            return json.dumps({"count": len(r), "results": r})
        elif name == "get_catalog_stats":
            stats = _get_stats()
            return json.dumps({"sources": stats, "totals": {
                "files": sum(s.get("files") or 0 for s in stats),
                "total_bytes": sum(s.get("total_bytes") or 0 for s in stats),
            }})
        elif name == "browse_folder":
            r = _browse_folder(inputs["source_id"], inputs.get("path", "/"),
                               int(inputs.get("limit", 50)))
            return json.dumps({"path": inputs.get("path", "/"), "entries": r})
        elif name == "find_large_files":
            return json.dumps({"results": _find_large_files(
                inputs.get("source_id"), int(inputs.get("limit", 20)))})
        elif name == "find_recent_files":
            return json.dumps({"results": _find_recent_files(
                inputs.get("source_id"), int(inputs.get("limit", 20)))})
        elif name == "search_by_type":
            return json.dumps({"results": _search_by_type(
                inputs["type"], inputs.get("source_id"), int(inputs.get("limit", 30)))})
        elif name == "get_type_breakdown":
            return json.dumps({"breakdown": _type_breakdown(inputs.get("source_id"))})
        else:
            return json.dumps({"error": f"Unknown tool: {name}"})
    except Exception as e:
        logger.error(f"Tool error [{name}]: {e}")
        return json.dumps({"error": str(e)})


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are Deep42 — a personal AI assistant with access to a local file catalog.
Files are indexed in a local SQLite database. You can search, browse, and analyse this catalog.

Personality: concise, direct, helpful. You are a brilliant personal archivist who knows the
user's files better than they do.

Rules:
- ALWAYS use tools to answer questions about files — never invent names or paths.
- Format results clearly: name, path, size (converted to KB/MB/GB), source.
- When searches return many results, summarise the pattern, highlight the most relevant.
- If nothing is found, say so clearly and suggest alternative searches.
- Keep responses short — the user is often on mobile.
- Never fabricate file paths. If a tool returns empty, say so honestly."""


# ── Tool schema: Anthropic format ─────────────────────────────────────────────

TOOLS_ANTHROPIC = [
    {
        "name": "search_files",
        "description": "Search files/folders by name. Use for 'find', 'where is', 'do I have', 'show me'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query":     {"type": "string",  "description": "Filename or keyword"},
                "source_id": {"type": "string",  "description": "Optional: limit to one source ID"},
                "limit":     {"type": "integer", "description": "Max results (default 20, max 50)", "default": 20},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_catalog_stats",
        "description": "Overview of all indexed sources — counts, sizes. Use for 'what do you have', 'how many files'.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "browse_folder",
        "description": "List contents of a folder path within a source.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_id": {"type": "string",  "description": "Source ID"},
                "path":      {"type": "string",  "description": "Folder path e.g. '/Documents/Work'", "default": "/"},
                "limit":     {"type": "integer", "description": "Max entries", "default": 50},
            },
            "required": ["source_id"],
        },
    },
    {
        "name": "find_large_files",
        "description": "Find biggest files. Use for 'what's taking up space', 'storage hogs'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_id": {"type": "string",  "description": "Optional source filter"},
                "limit":     {"type": "integer", "description": "Results count", "default": 20},
            },
        },
    },
    {
        "name": "find_recent_files",
        "description": "Most recently modified files. Use for 'what did I work on recently', 'latest files'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_id": {"type": "string",  "description": "Optional source filter"},
                "limit":     {"type": "integer", "description": "Results count", "default": 20},
            },
        },
    },
    {
        "name": "search_by_type",
        "description": (
            "Find files by type using extension or MIME category. "
            "Use for 'find all PDFs', 'show me my videos', 'how many Excel files', "
            "'list my images', 'find Word documents', 'show zip archives'. "
            "Pass a file extension like 'pdf', 'xlsx', 'mp4', 'docx', 'jpg' "
            "or a MIME category like 'image', 'video', 'audio'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "type":      {"type": "string",  "description": "Extension (e.g. 'pdf', 'mp4') or MIME category ('image', 'video', 'audio')"},
                "source_id": {"type": "string",  "description": "Optional: limit to a specific source"},
                "limit":     {"type": "integer", "description": "Max results", "default": 30},
            },
            "required": ["type"],
        },
    },
    {
        "name": "get_type_breakdown",
        "description": (
            "Show a breakdown of all file types in the catalog — how many of each "
            "extension and how much space they use. Use for 'what kinds of files do I have', "
            "'breakdown by type', 'what file types are indexed'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source_id": {"type": "string", "description": "Optional: limit to one source"},
            },
        },
    },
]

# ── Tool schema: OpenAI/Ollama format (auto-converted from Anthropic schema) ──

def _to_openai_tools(anthropic_tools: list) -> list:
    """Convert Anthropic tool schema → OpenAI/Ollama tool schema."""
    result = []
    for t in anthropic_tools:
        schema = dict(t["input_schema"])
        schema.pop("$schema", None)
        result.append({
            "type": "function",
            "function": {
                "name":        t["name"],
                "description": t["description"],
                "parameters":  schema,
            },
        })
    return result

TOOLS_OPENAI = _to_openai_tools(TOOLS_ANTHROPIC)


# ── SSE helper ────────────────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ── Backend: Ollama (OpenAI-compatible, 100% local) ───────────────────────────

def _stream_chat_ollama(messages: list):
    import urllib.request as urlreq

    host  = _ollama_host()
    model = _ollama_model()
    url   = f"{host}/v1/chat/completions"

    # Verify Ollama is running
    try:
        with urlreq.urlopen(f"{host}/api/tags", timeout=3):
            pass
    except Exception:
        yield _sse("error", {
            "message": f"Ollama not running at {host}. "
                       f"Start it with: ollama serve"
        })
        return

    MAX_ROUNDS = 5
    # OpenAI format: system prompt as first message
    current_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + list(messages)

    for round_num in range(MAX_ROUNDS):
        payload = json.dumps({
            "model":    model,
            "messages": current_messages,
            "tools":    TOOLS_OPENAI,
            "stream":   False,
        }).encode()

        req = urlreq.Request(url, data=payload,
                             headers={"Content-Type": "application/json"})

        try:
            with urlreq.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode())
        except Exception as e:
            yield _sse("error", {"message": f"Ollama error: {e}"})
            return

        choice       = result.get("choices", [{}])[0]
        finish       = choice.get("finish_reason", "stop")
        msg          = choice.get("message", {})
        content_text = msg.get("content") or ""
        tool_calls   = msg.get("tool_calls") or []

        # Stream any text content
        if content_text:
            yield _sse("text", {"text": content_text})

        # No tool calls → done
        if finish != "tool_calls" or not tool_calls:
            yield _sse("done", {})
            return

        # Execute tool calls
        tool_result_messages = []
        for tc in tool_calls:
            fn        = tc.get("function", {})
            tool_name = fn.get("name", "")
            try:
                tool_input = json.loads(fn.get("arguments", "{}"))
            except json.JSONDecodeError:
                tool_input = {}

            yield _sse("tool_call", {"name": tool_name, "input": tool_input})
            tool_output = _run_tool(tool_name, tool_input)
            yield _sse("tool_result", {"name": tool_name})

            tool_result_messages.append({
                "role":         "tool",
                "tool_call_id": tc.get("id", ""),
                "content":      tool_output,
            })

        # Append assistant turn + tool results and loop
        current_messages.append({
            "role":       "assistant",
            "content":    content_text or None,
            "tool_calls": tool_calls,
        })
        current_messages.extend(tool_result_messages)

    yield _sse("error", {"message": "Max tool rounds reached"})


# ── Backend: Anthropic (cloud fallback) ───────────────────────────────────────

def _stream_chat_anthropic(messages: list):
    import urllib.request as urlreq

    api_key = _anthropic_key()
    if not api_key:
        yield _sse("error", {"message": "ANTHROPIC_API_KEY not set and LLM_PROVIDER=anthropic"})
        return

    MAX_ROUNDS = 5
    current_messages = list(messages)

    for _ in range(MAX_ROUNDS):
        payload = json.dumps({
            "model":      _anthropic_model(),
            "max_tokens": 2048,
            "system":     SYSTEM_PROMPT,
            "tools":      TOOLS_ANTHROPIC,
            "messages":   current_messages,
        }).encode()

        req = urlreq.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
            },
        )

        try:
            with urlreq.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
        except Exception as e:
            yield _sse("error", {"message": f"Anthropic API error: {e}"})
            return

        stop_reason = result.get("stop_reason")
        content     = result.get("content", [])

        for block in content:
            if block.get("type") == "text":
                yield _sse("text", {"text": block["text"]})

        if stop_reason != "tool_use":
            yield _sse("done", {})
            return

        tool_calls   = [b for b in content if b.get("type") == "tool_use"]
        tool_results = []

        for tc in tool_calls:
            yield _sse("tool_call", {"name": tc["name"], "input": tc.get("input", {})})
            tool_results.append({
                "type":        "tool_result",
                "tool_use_id": tc["id"],
                "content":     _run_tool(tc["name"], tc.get("input", {})),
            })
            yield _sse("tool_result", {"name": tc["name"]})

        current_messages.append({"role": "assistant", "content": content})
        current_messages.append({"role": "user",      "content": tool_results})

    yield _sse("error", {"message": "Max tool rounds reached"})


# ── Router: pick backend from env ─────────────────────────────────────────────

def _stream_chat(messages: list):
    provider = _provider()
    if provider == "anthropic":
        logger.info("Using Anthropic backend")
        yield from _stream_chat_anthropic(messages)
    else:
        logger.info(f"Using Ollama backend — model: {_ollama_model()}")
        yield from _stream_chat_ollama(messages)


# ── Request models ────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list
    stream: bool = True


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/api/chat/health")
def chat_health(request: Request):
    _check_token(request)
    provider = _provider()
    info = {
        "status":    "ok",
        "catalog":   _db_path(),
        "node_role": NODE_ROLE,
        "provider":  provider,
        "fallback":  LLM_FALLBACK,
    }
    if provider == "anthropic":
        info["anthropic_model"] = _anthropic_model()
        info["anthropic_key_set"] = bool(_anthropic_key())
    else:
        info["model"]       = _ollama_model()
        info["ollama_host"] = _ollama_host()
    return info


@router.post("/api/chat")
async def chat(request: Request, body: ChatRequest):
    _check_token(request)
    ip = request.client.host if request.client else "unknown"
    _check_rate(ip)

    messages = [
        {"role": m["role"] if isinstance(m, dict) else m.role,
         "content": m["content"] if isinstance(m, dict) else m.content}
        for m in body.messages
    ]

    def stream_with_fallback():
        """Try primary provider; if it fails, transparently fall back."""
        primary  = _provider()
        fallback = LLM_FALLBACK

        try:
            # Attempt primary
            first_chunk = True
            for chunk in _stream_chat(messages):
                first_chunk = False
                yield chunk
            return
        except Exception as e:
            logger.warning(
                "Primary provider '%s' failed: %s — switching to fallback '%s'",
                primary, e, fallback
            )
            if first_chunk:
                # Nothing was sent yet — try fallback silently
                yield _sse("info", {"message": f"Using fallback provider: {fallback}"})

        # Fallback (only if different from primary and primary is not vault-locked Ollama)
        if fallback == "ollama" and primary != "ollama" and NODE_ROLE != "vault":
            try:
                yield from _stream_chat_ollama(messages)
            except Exception as fe:
                logger.error("Fallback also failed: %s", fe)
                yield _sse("error", {"message": "All LLM providers unavailable."})
        else:
            yield _sse("error", {"message": f"Primary provider '{primary}' failed. No fallback available."})

    return StreamingResponse(
        stream_with_fallback(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
