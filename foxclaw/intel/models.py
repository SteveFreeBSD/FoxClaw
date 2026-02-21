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
    transport: Literal["file", "https", "http"] = "file"
    insecure_transport: bool = False
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


class IntelExtensionBlocklistRecord(BaseModel):
    """Normalized extension blocklist record for local correlation."""

    addon_id: str
    version: str | None = None
    block_state: Literal["blocked", "soft_blocked"] = "blocked"
    reason: str | None = None
    reference_url: str | None = None


class IntelAmoExtensionRecord(BaseModel):
    """Normalized AMO extension intelligence record for local correlation."""

    addon_id: str
    version: str | None = None
    listed: bool = True
    reputation: Literal["low", "medium", "high"] = "low"
    review_rating: float | None = None
    review_count: int | None = None
    average_daily_users: int | None = None
    recommended: bool | None = None
    reason: str | None = None
    reference_url: str | None = None


class IntelNvdCveRecord(BaseModel):
    """Normalized NVD CVE metadata for deterministic enrichment."""

    cve_id: str
    severity: str | None = None
    summary: str | None = None
    reference_url: str | None = None


class IntelCveListRecord(BaseModel):
    """Normalized CVE list v5 metadata for deterministic enrichment."""

    cve_id: str
    severity: str | None = None
    summary: str | None = None
    reference_url: str | None = None


class IntelKevRecord(BaseModel):
    """Normalized CISA KEV metadata for deterministic enrichment."""

    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    known_ransomware_campaign_use: str | None = None
    short_description: str | None = None
    reference_url: str | None = None


class IntelEpssRecord(BaseModel):
    """Normalized EPSS metadata for deterministic enrichment."""

    cve_id: str
    score: float
    percentile: float | None = None
    reference_url: str | None = None


class IntelSourceIndex(BaseModel):
    """Normalized source-level index metadata written during sync."""

    source_name: str
    adapter: str | None = None
    schema_version: str | None = None
    record_count: int = 0
    mozilla_advisories: list[IntelMozillaAdvisoryRecord] = Field(default_factory=list)
    extension_blocklist: list[IntelExtensionBlocklistRecord] = Field(default_factory=list)
    amo_extension_intel: list[IntelAmoExtensionRecord] = Field(default_factory=list)
    nvd_cves: list[IntelNvdCveRecord] = Field(default_factory=list)
    cve_list_records: list[IntelCveListRecord] = Field(default_factory=list)
    kev_records: list[IntelKevRecord] = Field(default_factory=list)
    epss_records: list[IntelEpssRecord] = Field(default_factory=list)


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


class MozillaExtensionBlocklistBundle(BaseModel):
    """Canonical source payload schema for normalized extension blocklist data."""

    schema_version: Literal["foxclaw.mozilla.extension_blocklist.v1"]
    entries: list[IntelExtensionBlocklistRecord] = Field(default_factory=list)


class AmoExtensionIntelBundle(BaseModel):
    """Canonical source payload schema for AMO extension intelligence data."""

    schema_version: Literal["foxclaw.amo.extension_intel.v1"]
    records: list[IntelAmoExtensionRecord] = Field(default_factory=list)


class NvdCveRecordBundle(BaseModel):
    """Canonical source payload schema for normalized NVD CVE records."""

    schema_version: Literal["foxclaw.nvd.cve_records.v1"]
    records: list[IntelNvdCveRecord] = Field(default_factory=list)


class CveListRecordBundle(BaseModel):
    """Canonical source payload schema for normalized CVE list records."""

    schema_version: Literal["foxclaw.cve.list_records.v1"]
    records: list[IntelCveListRecord] = Field(default_factory=list)


class CisaKevBundle(BaseModel):
    """Canonical source payload schema for normalized CISA KEV entries."""

    schema_version: Literal["foxclaw.cisa.known_exploited_vulnerabilities.v1"]
    entries: list[IntelKevRecord] = Field(default_factory=list)


class EpssScoreBundle(BaseModel):
    """Canonical source payload schema for normalized EPSS score records."""

    schema_version: Literal["foxclaw.epss.scores.v1"]
    records: list[IntelEpssRecord] = Field(default_factory=list)
