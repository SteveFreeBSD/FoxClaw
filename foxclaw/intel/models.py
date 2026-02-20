"""Models for intelligence snapshot synchronization artifacts."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class IntelSourceMaterial(BaseModel):
    """Metadata for one fetched intelligence source payload."""

    name: str
    origin: str
    sha256: str
    size_bytes: int
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    artifact_path: str


class IntelSnapshotManifest(BaseModel):
    """Deterministic manifest for one synchronized intelligence snapshot."""

    schema_version: str = "1.0.0"
    snapshot_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_count: int
    sources: list[IntelSourceMaterial] = Field(default_factory=list)

