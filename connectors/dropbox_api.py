"""
connectors/dropbox_api.py — Dropbox connector for Deep42.

Handles:
  - OAuth2 PKCE flow with local callback
  - Full recursive scan via files/list_folder
  - Incremental scan via stored cursor
  - Team Space support (optional)
  - Metadata-only (no content download)
"""

import os
import secrets
import hashlib
import base64
import json
from typing import Iterator, Dict, Optional, Callable, Tuple
from datetime import datetime, timezone
import urllib.parse

try:
    import dropbox
    from dropbox.files import FolderMetadata, FileMetadata, DeletedMetadata
    DROPBOX_AVAILABLE = True
except ImportError:
    DROPBOX_AVAILABLE = False

# Read lazily so .env loaded in main.py takes effect before these are evaluated
def _key() -> str:     return os.environ.get("DROPBOX_APP_KEY", "")
def _secret() -> str:  return os.environ.get("DROPBOX_APP_SECRET", "")
def _redir() -> str:   return os.environ.get("DROPBOX_REDIRECT_URI", "http://localhost:8787/api/auth/dropbox/callback")

# Keep module-level names for backward compat — they re-read on each access
class _EnvStr(str):
    """A string subclass that re-reads from os.environ on each use."""
    def __new__(cls, fn):
        obj = str.__new__(cls, fn())
        obj._fn = fn
        return obj
    def __bool__(self):  return bool(self._fn())
    def __str__(self):   return self._fn()
    def __repr__(self):  return repr(self._fn())
    def __eq__(self, o): return self._fn() == o
    def __hash__(self):  return hash(self._fn())

DROPBOX_APP_KEY     = _EnvStr(_key)
DROPBOX_APP_SECRET  = _EnvStr(_secret)
DROPBOX_REDIRECT_URI = _EnvStr(_redir)

# In-memory state store for OAuth flow (keyed by state token)
_oauth_states: Dict[str, Dict] = {}


class DropboxConfigError(Exception):
    pass


def _require_keys():
    if not _key() or not _secret():
        raise DropboxConfigError(
            "DROPBOX_APP_KEY and DROPBOX_APP_SECRET must be set in environment. "
            "Create an app at https://www.dropbox.com/developers/apps"
        )


def _entry_to_dict(entry) -> Optional[Dict]:
    """Convert Dropbox SDK metadata entry to a Deep42 dict."""
    if isinstance(entry, DeletedMetadata):
        return None  # skip deletions in full scan context

    is_folder = isinstance(entry, FolderMetadata)
    path = entry.path_lower or entry.path_display or ""

    result = {
        "path": path,
        "name": entry.name,
        "entry_type": "folder" if is_folder else "file",
        "size": None,
        "modified_at": None,
        "dropbox_id": entry.id,
        "dropbox_rev": None,
        "dropbox_hash": None,
    }

    if isinstance(entry, FileMetadata):
        result["size"] = entry.size
        result["modified_at"] = entry.server_modified.isoformat() if entry.server_modified else None
        result["dropbox_rev"] = entry.rev
        result["dropbox_hash"] = entry.content_hash

    return result


# ─── OAuth Flow (standard OAuth2, no SDK flow classes) ───────────────────────

DROPBOX_AUTH_URL  = "https://www.dropbox.com/oauth2/authorize"
DROPBOX_TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"


def start_oauth_flow(account_type: str = "personal") -> Tuple[str, str]:
    """
    Build a Dropbox OAuth2 authorization URL and return it with a state token.
    Uses standard OAuth2 — no SDK flow classes needed.
    """
    _require_keys()

    state = secrets.token_urlsafe(24)
    _oauth_states[state] = {"account_type": account_type}

    params = urllib.parse.urlencode({
        "client_id":         _key(),
        "redirect_uri":      _redir(),
        "response_type":     "code",
        "state":             state,
        "token_access_type": "offline",   # request refresh token
    })
    auth_url = f"{DROPBOX_AUTH_URL}?{params}"
    return auth_url, state


def complete_oauth_flow(code: str, state: str) -> Dict:
    """
    Exchange an authorization code for tokens using the Dropbox token endpoint.
    Returns token_data dict with access_token, refresh_token, account_id, etc.
    """
    import urllib.request
    _require_keys()

    if state not in _oauth_states:
        raise ValueError("Invalid or expired OAuth state token.")

    state_data = _oauth_states.pop(state)

    # POST to token endpoint
    post_data = urllib.parse.urlencode({
        "code":          code,
        "grant_type":    "authorization_code",
        "client_id":     _key(),
        "client_secret": _secret(),
        "redirect_uri":  _redir(),
    }).encode()

    req = urllib.request.Request(
        DROPBOX_TOKEN_URL,
        data=post_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
    except Exception as e:
        raise ValueError(f"Token exchange failed: {e}")

    if "error" in result:
        raise ValueError(f"Dropbox error: {result.get('error_description', result['error'])}")

    return {
        "access_token":  result.get("access_token"),
        "refresh_token": result.get("refresh_token"),
        "account_id":    result.get("account_id"),
        "account_type":  state_data["account_type"],
        "token_type":    "bearer",
    }


def get_dropbox_client(token_data: dict, teamspace_enabled: bool = False):
    """Return an authenticated Dropbox client."""
    _require_keys()
    if not DROPBOX_AVAILABLE:
        raise DropboxConfigError("dropbox Python package not installed.")

    kwargs = {
        "oauth2_access_token": token_data["access_token"],
        "app_key": _key(),
        "app_secret": _secret(),
    }
    if token_data.get("refresh_token"):
        kwargs["oauth2_refresh_token"] = token_data["refresh_token"]

    return dropbox.Dropbox(**kwargs)


def get_account_info(token_data: dict) -> Dict:
    """Return basic account info for a connected portal."""
    dbx = get_dropbox_client(token_data)
    try:
        acct = dbx.users_get_current_account()
        return {
            "display_name": acct.name.display_name,
            "email": acct.email,
            "account_id": acct.account_id,
        }
    except Exception as e:
        return {"error": str(e)}


# ─── Full Scan ───────────────────────────────────────────────────────────────

def scan_dropbox_full(
    token_data: dict,
    cloud_root: str = "",
    teamspace_enabled: bool = False,
    on_progress: Optional[Callable[[int], None]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Tuple[Iterator[Dict], str]:
    """
    Full recursive scan of a Dropbox path.
    Yields entry dicts, returns the final cursor via generator send() protocol.

    Usage:
        entries, get_cursor = scan_dropbox_full(...)
        final_cursor = None
        for entry in entries:
            ...
        final_cursor = get_cursor()
    """
    dbx = get_dropbox_client(token_data, teamspace_enabled)
    path = cloud_root.rstrip("/") if cloud_root else ""

    def _generator() -> Iterator[Dict]:
        count = 0
        result = dbx.files_list_folder(path, recursive=True, include_deleted=False)

        while True:
            if should_cancel and should_cancel():
                return

            for entry in result.entries:
                d = _entry_to_dict(entry)
                if d:
                    yield d
                    count += 1
                    if on_progress and count % 200 == 0:
                        on_progress(count)

            if not result.has_more:
                # Store the cursor for incremental use
                _generator._cursor = result.cursor
                return

            result = dbx.files_list_folder_continue(result.cursor)

    gen = _generator()
    gen._cursor = None  # type: ignore
    return gen


def get_cursor_after_full_scan(generator) -> Optional[str]:
    return getattr(generator, "_cursor", None)


# ─── Incremental Scan ────────────────────────────────────────────────────────

def scan_dropbox_incremental(
    token_data: dict,
    cursor: str,
    teamspace_enabled: bool = False,
    on_progress: Optional[Callable[[int], None]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Tuple[Iterator[Dict], str]:
    """
    Incremental scan using a stored cursor.
    Yields changed/new entries. Deleted entries have entry_type='deleted'.
    Returns the new cursor after iteration.
    """
    dbx = get_dropbox_client(token_data, teamspace_enabled)

    def _generator():
        count = 0
        result = dbx.files_list_folder_continue(cursor)

        while True:
            if should_cancel and should_cancel():
                return

            for entry in result.entries:
                if isinstance(entry, DeletedMetadata):
                    yield {
                        "path": entry.path_lower or "",
                        "name": entry.name,
                        "entry_type": "deleted",
                        "size": None,
                        "modified_at": None,
                        "dropbox_id": None,
                        "dropbox_rev": None,
                        "dropbox_hash": None,
                    }
                else:
                    d = _entry_to_dict(entry)
                    if d:
                        yield d
                        count += 1
                        if on_progress and count % 200 == 0:
                            on_progress(count)

            if not result.has_more:
                _generator._cursor = result.cursor
                return

            result = dbx.files_list_folder_continue(result.cursor)

    gen = _generator()
    gen._cursor = None  # type: ignore
    return gen


# ─── Browse (live, non-cached) ───────────────────────────────────────────────

def browse_dropbox_live(
    token_data: dict,
    path: str = "",
    teamspace_enabled: bool = False,
) -> Iterator[Dict]:
    """
    List direct children of a Dropbox path (non-recursive, live API call).
    Used for the browse UI before a full scan is run.
    """
    dbx = get_dropbox_client(token_data, teamspace_enabled)
    norm_path = path.rstrip("/") if path and path != "/" else ""

    try:
        result = dbx.files_list_folder(norm_path, recursive=False, include_deleted=False)
    except Exception as e:
        raise RuntimeError(f"Dropbox browse failed: {e}")

    for entry in result.entries:
        d = _entry_to_dict(entry)
        if d:
            yield d

    while result.has_more:
        result = dbx.files_list_folder_continue(result.cursor)
        for entry in result.entries:
            d = _entry_to_dict(entry)
            if d:
                yield d
