"""Vendor-neutral SIEM NDJSON rendering helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from foxclaw.models import SEVERITY_ORDER, EvidenceBundle, Finding
from foxclaw.report.fleet import (
    _build_host_metadata,
    _build_profile_identity,
    _normalize_profile_path,
)

SIEM_SCHEMA_VERSION = "1.0.0"

_BASE_REQUIRED_FIELDS: tuple[str, ...] = (
    "schema_version",
    "timestamp",
    "event_type",
    "event_id",
    "host",
    "profile",
    "severity",
    "title",
    "message",
)
_FINDING_REQUIRED_FIELDS: tuple[str, ...] = (
    *_BASE_REQUIRED_FIELDS,
    "scan_id",
    "rule_id",
    "category",
    "confidence",
)
_SUMMARY_REQUIRED_FIELDS: tuple[str, ...] = (
    *_BASE_REQUIRED_FIELDS,
    "scan_id",
    "findings_total",
    "findings_high_count",
    "findings_medium_count",
    "findings_info_count",
    "findings_suppressed_count",
)


def iter_siem_events(bundle: EvidenceBundle) -> Iterable[dict[str, object]]:
    """Yield deterministic SIEM events for a scan bundle."""
    host = _build_host_metadata()
    normalized_profile_path = _normalize_profile_path(Path(bundle.profile.path))
    profile_identity = _build_profile_identity(
        profile_id=bundle.profile.profile_id,
        profile_name=bundle.profile.name,
        profile_path=normalized_profile_path,
    )
    timestamp = _format_timestamp(bundle.generated_at)
    scan_id = _build_scan_id(
        timestamp=timestamp,
        host_id=host.host_id,
        profile_id=profile_identity.profile_id,
    )
    host_payload: dict[str, object] = {
        "id": host.host_id,
        "name": host.hostname,
        "fqdn": host.fqdn,
    }
    profile_payload: dict[str, object] = {
        "profile_id": profile_identity.profile_id,
        "profile_uid": profile_identity.profile_uid,
        "name": profile_identity.name,
    }

    findings = sorted(bundle.findings, key=_finding_sort_key)
    for finding in findings:
        event = _build_finding_event(
            finding=finding,
            timestamp=timestamp,
            scan_id=scan_id,
            host=host_payload,
            profile=profile_payload,
        )
        _validate_event(event)
        yield event

    summary_event = _build_summary_event(
        bundle=bundle,
        timestamp=timestamp,
        scan_id=scan_id,
        host=host_payload,
        profile=profile_payload,
    )
    _validate_event(summary_event)
    yield summary_event


def write_ndjson(events: Iterable[dict[str, object]], out: TextIO) -> None:
    """Write one compact JSON object per line."""
    for event in events:
        _validate_event(event)
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        if "\n" in line or "\r" in line:
            raise ValueError(
                f"Invalid SIEM event for {event.get('event_type', '<unknown>')}: "
                "serialized NDJSON line contains a newline character."
            )
        out.write(line)
        out.write("\n")


def _build_finding_event(
    *,
    finding: Finding,
    timestamp: str,
    scan_id: str,
    host: Mapping[str, object],
    profile: Mapping[str, object],
) -> dict[str, object]:
    event: dict[str, object] = {
        "schema_version": SIEM_SCHEMA_VERSION,
        "timestamp": timestamp,
        "event_type": "foxclaw.finding",
        "host": host,
        "profile": profile,
        "severity": finding.severity,
        "title": finding.title,
        "message": finding.rationale,
        "scan_id": scan_id,
        "rule_id": finding.id,
        "category": finding.category,
        "confidence": finding.confidence,
        "rationale": finding.rationale,
        "recommendation": finding.recommendation,
        "evidence": list(finding.evidence),
    }
    if finding.risk_priority is not None:
        event["risk_priority"] = finding.risk_priority
    if finding.risk_factors:
        event["risk_factors"] = list(finding.risk_factors)
    event["event_id"] = _build_event_id(
        event_type="foxclaw.finding",
        host_id=str(host["id"]),
        profile_id=str(profile["profile_id"]),
        timestamp=timestamp,
        schema_version=SIEM_SCHEMA_VERSION,
        rule_id=finding.id,
    )
    return event


def _build_summary_event(
    *,
    bundle: EvidenceBundle,
    timestamp: str,
    scan_id: str,
    host: Mapping[str, object],
    profile: Mapping[str, object],
) -> dict[str, object]:
    event: dict[str, object] = {
        "schema_version": SIEM_SCHEMA_VERSION,
        "timestamp": timestamp,
        "event_type": "foxclaw.scan.summary",
        "host": host,
        "profile": profile,
        "severity": "INFO",
        "title": "FoxClaw scan summary",
        "message": (
            "Scan completed with "
            f"{bundle.summary.findings_total} findings, "
            f"{bundle.summary.findings_suppressed_count} suppressed, "
            "and 0 operational errors."
        ),
        "scan_id": scan_id,
        "findings_total": bundle.summary.findings_total,
        "findings_high_count": bundle.summary.findings_high_count,
        "findings_medium_count": bundle.summary.findings_medium_count,
        "findings_info_count": bundle.summary.findings_info_count,
        "findings_suppressed_count": bundle.summary.findings_suppressed_count,
    }
    event["event_id"] = _build_event_id(
        event_type="foxclaw.scan.summary",
        host_id=str(host["id"]),
        profile_id=str(profile["profile_id"]),
        timestamp=timestamp,
        schema_version=SIEM_SCHEMA_VERSION,
    )
    return event


def _build_event_id(
    *,
    event_type: str,
    host_id: str,
    profile_id: str,
    timestamp: str,
    schema_version: str,
    rule_id: str | None = None,
) -> str:
    # Canonical event_id material is a fixed pipe-delimited field order:
    # event_type=<value>|host.id=<value>|profile.profile_id=<value>|rule_id=<value>|timestamp=<value>|schema_version=<value>
    # Summary events omit the rule_id segment entirely.
    parts = [
        f"event_type={event_type}",
        f"host.id={host_id}",
        f"profile.profile_id={profile_id}",
    ]
    if rule_id is not None:
        parts.append(f"rule_id={rule_id}")
    parts.extend(
        [
            f"timestamp={timestamp}",
            f"schema_version={schema_version}",
        ]
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _build_scan_id(*, timestamp: str, host_id: str, profile_id: str) -> str:
    raw = "|".join(
        [
            f"timestamp={timestamp}",
            f"host.id={host_id}",
            f"profile.profile_id={profile_id}",
            f"schema_version={SIEM_SCHEMA_VERSION}",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _validate_event(event: dict[str, object]) -> None:
    event_type = str(event.get("event_type") or "<unknown>")
    if event_type == "foxclaw.finding":
        required_fields = _FINDING_REQUIRED_FIELDS
    elif event_type == "foxclaw.scan.summary":
        required_fields = _SUMMARY_REQUIRED_FIELDS
    else:
        raise ValueError(f"Invalid SIEM event type: {event_type}")

    for field in required_fields:
        value = event.get(field)
        if value is None or value == "":
            raise ValueError(f"Invalid SIEM event for {event_type}: missing required field {field}.")

    if event_type == "foxclaw.scan.summary" and "rule_id" in event:
        raise ValueError("Invalid SIEM event for foxclaw.scan.summary: rule_id must be omitted.")

    timestamp = event["timestamp"]
    if not isinstance(timestamp, str):
        raise ValueError(f"Invalid SIEM event for {event_type}: timestamp must be a string.")
    _parse_timestamp(timestamp, event_type=event_type)

    host = event["host"]
    if not isinstance(host, dict) or not host.get("id") or not host.get("name"):
        raise ValueError(f"Invalid SIEM event for {event_type}: host.id and host.name are required.")

    profile = event["profile"]
    if not isinstance(profile, dict) or not profile.get("profile_id") or not profile.get("name"):
        raise ValueError(
            f"Invalid SIEM event for {event_type}: profile.profile_id and profile.name are required."
        )


def _parse_timestamp(timestamp: str, *, event_type: str) -> None:
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"Invalid SIEM event for {event_type}: timestamp must be RFC3339/ISO8601 UTC."
        ) from exc


def _format_timestamp(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    return normalized.isoformat().replace("+00:00", "Z")


def _finding_sort_key(finding: Finding) -> tuple[int, str, tuple[str, ...]]:
    return (
        SEVERITY_ORDER.get(finding.severity, 99),
        finding.id,
        tuple(finding.evidence),
    )
