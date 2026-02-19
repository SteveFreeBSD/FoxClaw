"""Shared evidence models for scan collection."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, RootModel, StrictBool, StrictInt, StrictStr


PrefSource = Literal["prefs.js", "user.js", "unset"]
PrefRawType = Literal["bool", "int", "string"]


class PrefValue(BaseModel):
    """Single preference value with source metadata."""

    value: StrictBool | StrictInt | StrictStr
    source: PrefSource
    raw_type: PrefRawType


class PrefEvidence(RootModel[dict[str, PrefValue]]):
    """Preferences evidence as key -> value/source/type mapping."""


class FilePermEvidence(BaseModel):
    """Filesystem permission evidence for sensitive Firefox files."""

    path: str
    mode: str
    owner_uid: int | None = None
    owner_gid: int | None = None
    group_readable: bool
    group_writable: bool
    world_readable: bool
    world_writable: bool
    recommended_chmod: str | None = None


class PolicyFileSummary(BaseModel):
    """Summary of a discovered policies.json file."""

    path: str
    top_level_keys: list[str] = Field(default_factory=list)
    policies_count: int | None = None
    parse_error: str | None = None


class PolicyEvidence(BaseModel):
    """Discovered policy files and parsed summaries."""

    searched_paths: list[str] = Field(default_factory=list)
    discovered_paths: list[str] = Field(default_factory=list)
    summaries: list[PolicyFileSummary] = Field(default_factory=list)


class SqliteCheck(BaseModel):
    """Result of read-only SQLite quick_check for one database."""

    db_path: str
    opened_ro: bool
    quick_check_result: str


class SqliteEvidence(BaseModel):
    """SQLite quick_check evidence collection set."""

    checks: list[SqliteCheck] = Field(default_factory=list)


class ProfileEvidence(BaseModel):
    """Selected profile metadata for a scan."""

    profile_id: str
    name: str
    path: str
    selected: bool
    selection_reason: str | None = None
    lock_detected: bool
    lock_files: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """Computed counts used for human summaries and exit-code logic."""

    prefs_parsed: int
    sensitive_files_checked: int
    high_risk_perms_count: int
    policies_found: int
    sqlite_checks_total: int
    sqlite_non_ok_count: int
    high_findings_count: int


class EvidenceBundle(BaseModel):
    """Scan evidence package."""

    schema_version: str = "1.0.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    profile: ProfileEvidence
    prefs: PrefEvidence
    filesystem: list[FilePermEvidence] = Field(default_factory=list)
    policies: PolicyEvidence
    sqlite: SqliteEvidence
    summary: ScanSummary
    high_findings: list[str] = Field(default_factory=list)
