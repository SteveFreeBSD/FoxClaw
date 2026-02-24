"""Shared evidence models for scan collection."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, RootModel, StrictBool, StrictInt, StrictStr

from foxclaw.intel.models import IntelCorrelationEvidence

PrefSource = Literal["prefs.js", "user.js", "unset"]
PrefRawType = Literal["bool", "int", "string"]
FindingSeverity = Literal["INFO", "MEDIUM", "HIGH"]
FindingConfidence = Literal["low", "medium", "high"]
RiskPriority = Literal["low", "medium", "high", "critical"]


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
    key_paths: list[str] = Field(default_factory=list)
    policies_count: int | None = None
    parse_error: str | None = None


class PolicyEvidence(BaseModel):
    """Discovered policy files and parsed summaries."""

    searched_paths: list[str] = Field(default_factory=list)
    discovered_paths: list[str] = Field(default_factory=list)
    summaries: list[PolicyFileSummary] = Field(default_factory=list)


class ExtensionPermissionRisk(BaseModel):
    """One extension permission flagged with a risk level."""

    permission: str
    level: Literal["medium", "high"]
    reason: str


class ExtensionEntry(BaseModel):
    """Parsed extension metadata from extensions.json and manifest content."""

    addon_id: str
    name: str | None = None
    version: str | None = None
    active: bool | None = None
    addon_type: str | None = None
    location: str | None = None
    source_kind: Literal["profile", "system", "builtin", "external", "unknown"] = "unknown"
    source: str | None = None
    debug_install: bool = False
    debug_reason: str | None = None
    signed_state: str | None = None
    signed_valid: bool | None = None
    signed_status: Literal["valid", "invalid", "unavailable"] = "unavailable"
    manifest_path: str | None = None
    manifest_status: Literal["parsed", "unavailable", "error"] = "unavailable"
    manifest_version: int | None = None
    permissions: list[str] = Field(default_factory=list)
    host_permissions: list[str] = Field(default_factory=list)
    risky_permissions: list[ExtensionPermissionRisk] = Field(default_factory=list)
    blocklisted: bool | None = None
    intel_source: str | None = None
    intel_reference_url: str | None = None
    intel_version: str | None = None
    intel_reputation_level: Literal["low", "medium", "high"] | None = None
    intel_listed: bool | None = None
    intel_review_count: int | None = None
    intel_average_daily_users: int | None = None
    intel_recommended: bool | None = None
    intel_reason: str | None = None
    parse_error: str | None = None


class ExtensionEvidence(BaseModel):
    """Extension inventory and posture evidence."""

    extensions_json_path: str | None = None
    parse_error: str | None = None
    addons_seen: int = 0
    active_addons: int = 0
    entries: list[ExtensionEntry] = Field(default_factory=list)


class SqliteCheck(BaseModel):
    """Result of read-only SQLite quick_check for one database."""

    db_path: str
    opened_ro: bool
    quick_check_result: str


class SqliteEvidence(BaseModel):
    """SQLite quick_check evidence collection set."""

    checks: list[SqliteCheck] = Field(default_factory=list)


class ProfileArtifactEntry(BaseModel):
    """One staged profile artifact metadata record."""

    rel_path: str
    size: int | None = None
    mtime_utc: str | None = None
    sha256: str | None = None
    parse_status: Literal["metadata_only", "parsed", "error"] = "metadata_only"
    top_level_keys: list[str] = Field(default_factory=list)
    key_values: dict[str, str] = Field(default_factory=dict)
    parse_error: str | None = None


class ProfileArtifactEvidence(BaseModel):
    """Additional profile artifact metadata collected during scan."""

    schema_version: str = "1.0.0"
    entries: list[ProfileArtifactEntry] = Field(default_factory=list)


class CredentialEvidence(BaseModel):
    """Credential and password-leak posture evidence derived from profile artifacts."""

    logins_present: bool = False
    logins_parse_error: str | None = None
    saved_logins_count: int = 0
    vulnerable_passwords_count: int = 0
    dismissed_breach_alerts_count: int = 0
    insecure_http_login_count: int = 0
    formhistory_present: bool = False
    formhistory_opened_ro: bool = False
    formhistory_parse_error: str | None = None
    formhistory_password_field_count: int = 0
    formhistory_credential_field_count: int = 0


class Finding(BaseModel):
    """Single posture finding produced by rule evaluation."""

    id: str
    title: str
    severity: FindingSeverity
    category: str
    rationale: str
    recommendation: str
    confidence: FindingConfidence
    risk_priority: RiskPriority | None = None
    risk_factors: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class SuppressionScope(BaseModel):
    """Scope constraint for applying a suppression rule."""

    profile_glob: str = "*"
    evidence_contains: str | None = None


class ApprovalType(StrEnum):
    """Allowed justification types for suppression governance."""

    ACCEPTED_RISK = "accepted_risk"
    MITIGATING_CONTROL = "mitigating_control"
    FALSE_POSITIVE = "false_positive"
    TEMPORARY_EXCEPTION = "temporary_exception"


class SuppressionApproval(BaseModel):
    """Governance block enforcing approval and audit trails."""

    requested_by: str
    requested_at: datetime
    approved_by: str
    approved_at: datetime
    ticket: str
    justification_type: ApprovalType


class SuppressionEntry(BaseModel):
    """One suppression declaration loaded from policy files."""

    id: str | None = None
    rule_id: str
    owner: str
    reason: str
    expires_at: datetime
    scope: SuppressionScope
    approval: SuppressionApproval | None = None


class SuppressionPolicy(BaseModel):
    """Suppression policy file contract."""

    schema_version: str = "1.0.0"
    suppressions: list[SuppressionEntry] = Field(default_factory=list)


class AppliedSuppression(BaseModel):
    """One applied suppression mapped to a finding."""

    id: str | None = None
    rule_id: str
    owner: str
    reason: str
    expires_at: datetime
    source_path: str
    evidence_match: str | None = None
    approval: SuppressionApproval | None = None


class SuppressionEvidence(BaseModel):
    """Suppression loading/apply telemetry for the scan."""

    source_paths: list[str] = Field(default_factory=list)
    applied: list[AppliedSuppression] = Field(default_factory=list)
    expired: list[AppliedSuppression] = Field(default_factory=list)
    
    # Governance tracing
    applied_by_owner: dict[str, int] = Field(default_factory=dict)
    applied_by_approver: dict[str, int] = Field(default_factory=dict)
    expiring_within_30d: list[AppliedSuppression] = Field(default_factory=list)
    legacy_schema_count: int = 0


class RuleDefinition(BaseModel):
    """Rule definition loaded from a YAML ruleset."""

    id: str
    title: str
    severity: FindingSeverity
    category: str
    check: dict[str, object]
    rationale: str
    recommendation: str
    confidence: FindingConfidence


class BundleProvenance(BaseModel):
    """Metadata about the external bundle this ruleset was loaded from."""

    bundle_name: str
    bundle_version: str
    manifest_signature: str
    verified_at: datetime


class Ruleset(BaseModel):
    """Ruleset metadata and entries."""

    name: str
    version: str
    min_firefox_major: int | None = None
    rules: list[RuleDefinition] = Field(default_factory=list)
    bundle_provenance: BundleProvenance | None = None


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
    extensions_found: int = 0
    extensions_active: int = 0
    extensions_high_risk_count: int = 0
    extensions_unsigned_count: int = 0
    extensions_debug_count: int = 0
    sqlite_checks_total: int
    sqlite_non_ok_count: int
    intel_matches_count: int = 0
    findings_total: int = 0
    findings_high_count: int = 0
    findings_medium_count: int = 0
    findings_info_count: int = 0
    findings_suppressed_count: int = 0


class EvidenceBundle(BaseModel):
    """Scan evidence package."""

    schema_version: str = "1.0.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    profile: ProfileEvidence
    prefs: PrefEvidence
    filesystem: list[FilePermEvidence] = Field(default_factory=list)
    policies: PolicyEvidence
    extensions: ExtensionEvidence = Field(default_factory=ExtensionEvidence)
    sqlite: SqliteEvidence
    artifacts: ProfileArtifactEvidence = Field(default_factory=ProfileArtifactEvidence)
    credentials: CredentialEvidence = Field(default_factory=CredentialEvidence)
    intel: IntelCorrelationEvidence = Field(default_factory=IntelCorrelationEvidence)
    summary: ScanSummary
    high_findings: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    suppressions: SuppressionEvidence = Field(default_factory=SuppressionEvidence)
    bundle_provenance: BundleProvenance | None = None


class FleetHostMetadata(BaseModel):
    """Deterministic host identity metadata for fleet aggregation outputs."""

    host_id: str
    hostname: str
    fqdn: str
    os_name: str
    os_release: str
    os_version: str
    architecture: str
    machine_id_sha256: str | None = None


class FleetProfileIdentity(BaseModel):
    """Deterministic profile identity used in fleet outputs."""

    profile_uid: str
    profile_id: str
    name: str
    path: str


class FleetProfileReport(BaseModel):
    """Normalized per-profile fleet output contract."""

    identity: FleetProfileIdentity
    evidence_schema_version: str
    summary: ScanSummary
    high_findings: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    intel_snapshot_id: str | None = None


class FleetFindingRecord(BaseModel):
    """Flattened finding record for downstream SIEM/fleet ingestion."""

    host_id: str
    profile_uid: str
    profile_id: str
    profile_name: str
    profile_path: str
    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    confidence: FindingConfidence
    rationale: str
    recommendation: str
    risk_priority: RiskPriority | None = None
    risk_factors: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    intel_snapshot_id: str | None = None


class FleetAggregateSummary(BaseModel):
    """Fleet-level aggregate counters for merged profile outputs."""

    profiles_total: int
    profiles_with_findings: int
    profiles_with_high_findings: int
    findings_total: int
    findings_high_count: int
    findings_medium_count: int
    findings_info_count: int
    findings_suppressed_count: int
    unique_rule_ids: list[str] = Field(default_factory=list)


class FleetAggregationReport(BaseModel):
    """Top-level fleet aggregation report contract."""

    fleet_schema_version: str = "1.0.0"
    host: FleetHostMetadata
    aggregate: FleetAggregateSummary
    profiles: list[FleetProfileReport] = Field(default_factory=list)
    finding_records: list[FleetFindingRecord] = Field(default_factory=list)


class SnapshotRulesetMetadata(BaseModel):
    """Ruleset provenance metadata for deterministic snapshots."""

    name: str
    version: str
    path: str
    sha256: str


class ScanSnapshot(BaseModel):
    """Deterministic snapshot payload for baseline and diff workflows."""

    snapshot_schema_version: str = "1.0.0"
    evidence_schema_version: str
    profile: ProfileEvidence
    ruleset: SnapshotRulesetMetadata
    intel: IntelCorrelationEvidence = Field(default_factory=IntelCorrelationEvidence)
    summary: ScanSummary
    high_findings: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class SnapshotMetadata(BaseModel):
    """Core snapshot metadata used in diff payloads."""

    snapshot_schema_version: str
    evidence_schema_version: str
    profile: ProfileEvidence
    ruleset: SnapshotRulesetMetadata
    intel_snapshot_id: str | None = None


class SnapshotDiffSummary(BaseModel):
    """Summary counts for baseline-to-current snapshot drift."""

    drift_detected: bool
    before_findings_total: int
    after_findings_total: int
    before_findings_high_count: int
    after_findings_high_count: int
    before_findings_medium_count: int
    after_findings_medium_count: int
    before_findings_info_count: int
    after_findings_info_count: int
    added_findings_count: int
    removed_findings_count: int
    changed_findings_count: int


class SnapshotFindingChange(BaseModel):
    """One rule-level finding change between two snapshots."""

    rule_id: str
    before: Finding
    after: Finding


class ScanSnapshotDiff(BaseModel):
    """Deterministic snapshot-diff payload."""

    snapshot_diff_schema_version: str = "1.0.0"
    before: SnapshotMetadata
    after: SnapshotMetadata
    summary: SnapshotDiffSummary
    added_findings: list[Finding] = Field(default_factory=list)
    removed_findings: list[Finding] = Field(default_factory=list)
    changed_findings: list[SnapshotFindingChange] = Field(default_factory=list)
