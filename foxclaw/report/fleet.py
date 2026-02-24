"""Fleet aggregation rendering helpers."""

from __future__ import annotations

import hashlib
import json
import platform
import socket
from pathlib import Path

from foxclaw.models import (
    EvidenceBundle,
    FleetAggregateSummary,
    FleetAggregationReport,
    FleetFindingRecord,
    FleetHostMetadata,
    FleetProfileIdentity,
    FleetProfileReport,
    SEVERITY_ORDER,
)


def build_fleet_report(bundles: list[EvidenceBundle]) -> FleetAggregationReport:
    """Build deterministic fleet aggregation output for multiple profile scans."""
    host = _build_host_metadata()

    profiles: list[FleetProfileReport] = []
    finding_records: list[FleetFindingRecord] = []
    for bundle in bundles:
        normalized_path = _normalize_profile_path(Path(bundle.profile.path))
        identity = _build_profile_identity(
            profile_id=bundle.profile.profile_id,
            profile_name=bundle.profile.name,
            profile_path=normalized_path,
        )
        profile_report = FleetProfileReport(
            identity=identity,
            evidence_schema_version=bundle.schema_version,
            summary=bundle.summary,
            high_findings=sorted(bundle.high_findings),
            findings=bundle.findings,
            intel_snapshot_id=bundle.intel.snapshot_id,
        )
        profiles.append(profile_report)

        for finding in bundle.findings:
            finding_records.append(
                FleetFindingRecord(
                    host_id=host.host_id,
                    profile_uid=identity.profile_uid,
                    profile_id=identity.profile_id,
                    profile_name=identity.name,
                    profile_path=identity.path,
                    rule_id=finding.id,
                    title=finding.title,
                    severity=finding.severity,
                    category=finding.category,
                    confidence=finding.confidence,
                    rationale=finding.rationale,
                    recommendation=finding.recommendation,
                    risk_priority=finding.risk_priority,
                    risk_factors=finding.risk_factors,
                    evidence=finding.evidence,
                    intel_snapshot_id=bundle.intel.snapshot_id,
                )
            )

    profiles.sort(key=lambda item: (item.identity.profile_uid, item.identity.path))
    finding_records.sort(key=_finding_sort_key)
    aggregate = _build_aggregate_summary(profiles=profiles, finding_records=finding_records)
    return FleetAggregationReport(
        host=host,
        aggregate=aggregate,
        profiles=profiles,
        finding_records=finding_records,
    )


def render_fleet_json(report: FleetAggregationReport) -> str:
    """Render deterministic JSON for a fleet aggregation report."""
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)


def _build_aggregate_summary(
    *,
    profiles: list[FleetProfileReport],
    finding_records: list[FleetFindingRecord],
) -> FleetAggregateSummary:
    return FleetAggregateSummary(
        profiles_total=len(profiles),
        profiles_with_findings=sum(1 for item in profiles if item.summary.findings_total > 0),
        profiles_with_high_findings=sum(1 for item in profiles if item.summary.findings_high_count > 0),
        findings_total=sum(item.summary.findings_total for item in profiles),
        findings_high_count=sum(item.summary.findings_high_count for item in profiles),
        findings_medium_count=sum(item.summary.findings_medium_count for item in profiles),
        findings_info_count=sum(item.summary.findings_info_count for item in profiles),
        findings_suppressed_count=sum(item.summary.findings_suppressed_count for item in profiles),
        unique_rule_ids=sorted({item.rule_id for item in finding_records}),
    )


def _build_host_metadata() -> FleetHostMetadata:
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    architecture = platform.machine()
    machine_id = _read_machine_id()
    machine_id_sha256 = _sha256(machine_id) if machine_id is not None else None

    host_id_material = machine_id
    if host_id_material is None:
        host_id_material = "\n".join(
            [
                hostname,
                fqdn,
                os_name,
                os_release,
                os_version,
                architecture,
            ]
        )

    return FleetHostMetadata(
        host_id=_sha256(host_id_material),
        hostname=hostname,
        fqdn=fqdn,
        os_name=os_name,
        os_release=os_release,
        os_version=os_version,
        architecture=architecture,
        machine_id_sha256=machine_id_sha256,
    )


def _build_profile_identity(
    *,
    profile_id: str,
    profile_name: str,
    profile_path: str,
) -> FleetProfileIdentity:
    fingerprint_material = "\n".join([profile_id, profile_path])
    return FleetProfileIdentity(
        profile_uid=_sha256(fingerprint_material),
        profile_id=profile_id,
        name=profile_name,
        path=profile_path,
    )


def _normalize_profile_path(path: Path) -> str:
    return path.expanduser().resolve(strict=False).as_posix()


def _finding_sort_key(item: FleetFindingRecord) -> tuple[int, str, str, tuple[str, ...]]:
    return (
        SEVERITY_ORDER.get(item.severity, 99),
        item.rule_id,
        item.profile_uid,
        tuple(item.evidence),
    )


def _read_machine_id() -> str | None:
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
