"""
connectors/local_fs.py — Local filesystem connector for Deep42.

Walks a directory tree and yields metadata-only entry dicts.
No file content is read.
"""

import os
import stat
import mimetypes
from pathlib import Path
from datetime import datetime, timezone
from typing import Iterator, Dict, Optional, Callable

# Warm up the mimetypes database once at import time
mimetypes.init()


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _extension(name: str) -> Optional[str]:
    """Return lowercase extension without dot, or None for files with no extension."""
    if '.' not in name or name.startswith('.'):
        return None
    return name.rsplit('.', 1)[-1].lower()


def _mime(name: str) -> Optional[str]:
    """Guess MIME type from filename using stdlib mimetypes. Returns None if unknown."""
    mime, _ = mimetypes.guess_type(name, strict=False)
    return mime


def _birth_time(st: os.stat_result) -> Optional[str]:
    """Return file creation time (birth time).
    macOS: st_birthtime is always available.
    Linux: falls back to st_ctime (metadata change time, approximation).
    """
    ts = getattr(st, 'st_birthtime', None) or st.st_ctime
    return _ts(ts) if ts else None


def _safe_stat(path: str) -> Optional[os.stat_result]:
    try:
        return os.stat(path, follow_symlinks=False)
    except (PermissionError, FileNotFoundError, OSError):
        return None


def scan_local(
    root_path: str,
    on_progress: Optional[Callable[[int], None]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Iterator[Dict]:
    """
    Walk root_path recursively, yielding metadata dicts for each entry.
    Symlinks are skipped (not followed).
    Yields:
      { path, name, entry_type, size, modified_at }
    """
    root = Path(root_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Root path does not exist: {root}")

    count = 0
    root_str = str(root)  # pre-compute once
    root_prefix_len = len(root_str)
    stack = [root_str]

    while stack:
        if should_cancel and should_cancel():
            return

        current = stack.pop()
        try:
            entries = os.scandir(current)  # iterator, not list — saves memory
        except (PermissionError, OSError):
            continue

        with entries:  # ensure DirEntry iterator is closed
            for entry in entries:
                if should_cancel and should_cancel():
                    return

                # Skip symlinks
                if entry.is_symlink():
                    continue

                try:
                    st = entry.stat(follow_symlinks=False)
                except (PermissionError, OSError):
                    continue

                is_dir = stat.S_ISDIR(st.st_mode)

                # Build relative path with string slicing — no resolve() syscall
                abs_path = entry.path
                rel_path = abs_path[root_prefix_len:].replace("\\", "/") or "/"
                if not rel_path.startswith("/"):
                    rel_path = "/" + rel_path

                yield {
                    "path":       rel_path,
                    "name":       entry.name,
                    "entry_type": "folder" if is_dir else "file",
                    "extension":  None if is_dir else _extension(entry.name),
                    "mime_type":  None if is_dir else _mime(entry.name),
                    "size":       st.st_size if not is_dir else None,
                    "created_at": _birth_time(st),
                    "modified_at":_ts(st.st_mtime),
                }

                count += 1
                if on_progress and count % 500 == 0:  # less frequent DB writes
                    on_progress(count)

                if is_dir:
                    stack.append(abs_path)


def browse_local(root_path: str, sub_path: str = "/") -> Iterator[Dict]:
    """
    List direct children of root_path / sub_path (non-recursive).
    Yields metadata dicts with path relative to root_path.
    """
    root = Path(root_path).resolve()
    target = (root / sub_path.lstrip("/")).resolve()

    if not target.exists() or not target.is_dir():
        return

    try:
        entries = list(os.scandir(str(target)))
    except (PermissionError, OSError):
        return

    for entry in entries:
        if entry.is_symlink():
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except (PermissionError, OSError):
            continue

        is_dir = stat.S_ISDIR(st.st_mode)
        full_path = Path(entry.path).resolve()
        try:
            rel_path = "/" + str(full_path.relative_to(root)).replace("\\", "/")
        except ValueError:
            continue

        yield {
            "path": rel_path,
            "name": entry.name,
            "entry_type": "folder" if is_dir else "file",
            "size": st.st_size if not is_dir else None,
            "modified_at": _ts(st.st_mtime),
        }
