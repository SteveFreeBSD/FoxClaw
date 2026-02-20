"""Models for intelligence snapshot synchronization artifacts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


class IntelSourceMaterial(BaseModel):
    """Metadata for one fetched intelligence source payload."""

    name: str
    origin: str
    sha256: str
    size_bytes: int
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    artifact_path: str
    schema_version: str | None = None
    adapter: str | None = None
    records_indexed: int = 0


class IntelSnapshotManifest(BaseModel):
    """Deterministic manifest for one synchronized intelligence snapshot."""

    schema_version: str = "1.0.0"
    snapshot_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_count: int
    sources: list[IntelSourceMaterial] = Field(default_factory=list)


class IntelMozillaAdvisoryRecord(BaseModel):
    """Normalized Mozilla Firefox advisory record for local correlation."""

    advisory_id: str
    cve_id: str
    affected_versions: str
    fixed_version: str | None = None
    severity: str | None = None
    summary: str | None = None
    reference_url: str | None = None


class IntelSourceIndex(BaseModel):
    """Normalized source-level index metadata written during sync."""

    source_name: str
    adapter: str | None = None
    schema_version: str | None = None
    record_count: int = 0
    mozilla_advisories: list[IntelMozillaAdvisoryRecord] = Field(default_factory=list)


class IntelMatchedMozillaAdvisory(BaseModel):
    """One advisory row matched to the local Firefox version."""

    source_name: str
    advisory_id: str
    cve_id: str
    affected_versions: str
    fixed_version: str | None = None
    severity: str | None = None
    reference_url: str | None = None


class IntelCorrelationEvidence(BaseModel):
    """Scan-time vulnerability correlation evidence from local intel snapshots."""

    enabled: bool = False
    store_dir: str | None = None
    snapshot_id: str | None = None
    profile_firefox_version: str | None = None
    advisories_indexed: int = 0
    matched_advisories: list[IntelMatchedMozillaAdvisory] = Field(default_factory=list)
    error: str | None = None


class MozillaFirefoxAdvisoryBundle(BaseModel):
    """Canonical source payload schema for normalized Mozilla advisories."""

    schema_version: Literal["foxclaw.mozilla.firefox_advisories.v1"]
    product: Literal["firefox"] = "firefox"
    advisories: list[IntelMozillaAdvisoryRecord] = Field(default_factory=list)
