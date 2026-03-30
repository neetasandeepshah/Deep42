"""
models.py — Pydantic request/response schemas for Deep42 API.
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal, List
from datetime import datetime


# ─── Credentials ─────────────────────────────────────────────────────────────

class CredentialSummary(BaseModel):
    id: str
    provider: str
    created_at: str


# ─── Sources ─────────────────────────────────────────────────────────────────

SourceType = Literal["local_fs", "dropbox_user", "dropbox_team"]
PolicyType = Literal["include", "exclude"]


class SourceCreate(BaseModel):
    type: SourceType
    display_name: Optional[str] = None
    root_path: Optional[str] = None          # local_fs only
    cloud_root: Optional[str] = None         # portal: e.g. "/Work" or ""
    credentials_ref: Optional[str] = None    # portal only
    default_policy: PolicyType = "include"
    enabled: bool = True
    teamspace_enabled: bool = False
    notes: Optional[str] = None


class SourceOut(BaseModel):
    id: str
    type: str
    display_name: Optional[str] = None
    root_path: Optional[str] = None
    cloud_root: Optional[str] = None
    credentials_ref: Optional[str] = None
    default_policy: str
    enabled: bool
    teamspace_enabled: bool
    notes: Optional[str] = None
    created_at: str
    updated_at: str


# ─── Rules ───────────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    source_id: str
    path_prefix: str
    policy: PolicyType


class RuleOut(BaseModel):
    id: str
    source_id: str
    path_prefix: str
    policy: str
    created_at: Optional[str] = None


# ─── Browse ──────────────────────────────────────────────────────────────────

class BrowseItem(BaseModel):
    path: str
    name: str
    type: Literal["file", "folder"]
    effective_policy: PolicyType
    size: Optional[int] = None
    modified_at: Optional[str] = None


# ─── Search ──────────────────────────────────────────────────────────────────

class SearchResult(BaseModel):
    id: str
    source_id: str
    source_name: Optional[str] = None
    source_type: Optional[str] = None
    path: str
    name: str
    entry_type: str
    size: Optional[int] = None
    modified_at: Optional[str] = None
    indexed_at: Optional[str] = None


# ─── Scan Jobs ───────────────────────────────────────────────────────────────

ScanMode = Literal["manual", "incremental"]
ScanStatus = Literal["queued", "running", "done", "error", "canceled"]


class ScanJobOut(BaseModel):
    id: str
    source_id: str
    mode: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    items_scanned: int = 0
    items_included: int = 0
    items_excluded: int = 0
    error_message: Optional[str] = None
    created_at: str


# ─── OAuth / Dropbox ─────────────────────────────────────────────────────────

class DropboxAuthStart(BaseModel):
    account_type: Literal["personal", "business"] = "personal"


class DropboxAuthComplete(BaseModel):
    code: str
    state: str


# ─── Stats ───────────────────────────────────────────────────────────────────

class SourceStats(BaseModel):
    total: int = 0
    files: int = 0
    folders: int = 0
    total_bytes: Optional[int] = None
