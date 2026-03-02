"""Elastic Common Schema NDJSON rendering helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO, cast

from foxclaw import __version__
from foxclaw.models import SEVERITY_ORDER, EvidenceBundle, Finding, FleetHostMetadata, RiskPriority
from foxclaw.report.fleet import (
    _build_host_metadata,
    _build_profile_identity,
    _normalize_profile_path,
)

ECS_VERSION = "9.2.0"
FOXCLAW_ECS_SCHEMA_VERSION = "1.0.0"

_BASE_REQUIRED_FIELDS: tuple[str, ...] = (
    "@timestamp",
    "agent",
    "data_stream",
    "ecs",
    "event",
    "foxclaw",
    "host",
    "labels",
    "message",
    "observer",
)


def iter_ecs_events(bundle: EvidenceBundle) -> Iterable[dict[str, object]]:
    """Yield deterministic ECS events for a scan bundle."""
    host = _build_host_metadata()
    normalized_profile_path = _normalize_profile_path(Path(bundle.profile.path))
    profile_identity = _build_profile_identity(
        profile_id=bundle.profile.profile_id,
        profile_name=bundle.profile.name,
        profile_path=normalized_profile_path,
    )
    profile_payload: dict[str, object] = {
        "name": profile_identity.name,
        "profile_id": profile_identity.profile_id,
        "profile_uid": profile_identity.profile_uid,
    }
    timestamp = _format_timestamp(bundle.generated_at)
    scan_id = _build_scan_id(
        timestamp=timestamp,
        host_id=host.host_id,
        profile_id=profile_identity.profile_id,
    )

    findings = sorted(bundle.findings, key=_finding_sort_key)
    for finding in findings:
        event = _build_finding_event(
            finding=finding,
            timestamp=timestamp,
            scan_id=scan_id,
            host=host,
            profile=profile_payload,
        )
        _validate_event(event)
        yield event

    summary_event = _build_summary_event(
        bundle=bundle,
        timestamp=timestamp,
        scan_id=scan_id,
        host=host,
        profile=profile_payload,
    )
    _validate_event(summary_event)
    yield summary_event


def write_ecs_ndjson(events: Iterable[dict[str, object]], out: TextIO) -> None:
    """Write one compact ECS JSON object per line."""
    for event in events:
        _validate_event(event)
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        if "\n" in line or "\r" in line:
            event_id = _event_id_from_event(event)
            raise ValueError(
                "Invalid ECS event for "
                f"{event_id}: serialized NDJSON line contains a newline character."
            )
        out.write(line)
        out.write("\n")


def _build_finding_event(
    *,
    finding: Finding,
    timestamp: str,
    scan_id: str,
    host: FleetHostMetadata,
    profile: Mapping[str, object],
) -> dict[str, object]:
    event_id = _build_event_id(
        event_type="foxclaw.finding",
        host_id=host.host_id,
        profile_id=str(profile["profile_id"]),
        timestamp=timestamp,
        rule_id=finding.id,
    )
    event: dict[str, object] = _build_base_event(
        timestamp=timestamp,
        event_id=event_id,
        event_type="foxclaw.finding",
        kind="alert",
        category=["configuration", "host"],
        event_type_values=["info"],
        severity=finding.severity,
        message=finding.rationale,
        scan_id=scan_id,
        host=host,
        profile=profile,
    )
    event_payload = _require_object_dict(event.get("event"), field="event")
    event_payload["code"] = finding.id
    event_payload["severity"] = _severity_score(finding.severity)
    event["log"] = {"level": _log_level(finding.severity)}
    event["rule"] = {
        "author": ["FoxClaw"],
        "category": finding.category,
        "description": finding.rationale,
        "id": finding.id,
        "name": finding.title,
        "ruleset": "foxclaw",
    }
    if finding.risk_priority is not None:
        event_payload["risk_score_norm"] = _risk_score(finding.risk_priority)
    foxclaw_payload = _require_object_dict(event.get("foxclaw"), field="foxclaw")
    finding_payload: dict[str, object] = {
        "category": finding.category,
        "confidence": finding.confidence,
        "evidence": list(finding.evidence),
        "recommendation": finding.recommendation,
        "rule_id": finding.id,
        "severity": finding.severity,
        "title": finding.title,
    }
    if finding.risk_priority is not None:
        finding_payload["risk_priority"] = finding.risk_priority
    if finding.risk_factors:
        finding_payload["risk_factors"] = list(finding.risk_factors)
    foxclaw_payload["finding"] = finding_payload
    return event


def _build_summary_event(
    *,
    bundle: EvidenceBundle,
    timestamp: str,
    scan_id: str,
    host: FleetHostMetadata,
    profile: Mapping[str, object],
) -> dict[str, object]:
    event_id = _build_event_id(
        event_type="foxclaw.scan.summary",
        host_id=host.host_id,
        profile_id=str(profile["profile_id"]),
        timestamp=timestamp,
    )
    event: dict[str, object] = _build_base_event(
        timestamp=timestamp,
        event_id=event_id,
        event_type="foxclaw.scan.summary",
        kind="event",
        category=["host"],
        event_type_values=["info"],
        severity="INFO",
        message=(
            "Scan completed with "
            f"{bundle.summary.findings_total} findings, "
            f"{bundle.summary.findings_suppressed_count} suppressed, "
            "and 0 operational errors."
        ),
        scan_id=scan_id,
        host=host,
        profile=profile,
    )
    event_payload = _require_object_dict(event.get("event"), field="event")
    event_payload["code"] = "FOXCLAW_SCAN_SUMMARY"
    event_payload["outcome"] = "success"
    event_payload["severity"] = _severity_score("INFO")
    event["log"] = {"level": _log_level("INFO")}
    foxclaw_payload = _require_object_dict(event.get("foxclaw"), field="foxclaw")
    foxclaw_payload["summary"] = {
        "findings_high_count": bundle.summary.findings_high_count,
        "findings_info_count": bundle.summary.findings_info_count,
        "findings_medium_count": bundle.summary.findings_medium_count,
        "findings_suppressed_count": bundle.summary.findings_suppressed_count,
        "findings_total": bundle.summary.findings_total,
    }
    return event


def _build_base_event(
    *,
    timestamp: str,
    event_id: str,
    event_type: str,
    kind: str,
    category: list[str],
    event_type_values: list[str],
    severity: str,
    message: str,
    scan_id: str,
    host: FleetHostMetadata,
    profile: Mapping[str, object],
) -> dict[str, object]:
    host_payload = _build_ecs_host(host)
    return {
        "@timestamp": timestamp,
        "agent": {
            "name": "foxclaw",
            "type": "foxclaw",
            "version": __version__,
        },
        "data_stream": {
            "dataset": "foxclaw.scan",
            "namespace": "default",
            "type": "logs",
        },
        "ecs": {
            "version": ECS_VERSION,
        },
        "event": {
            "action": event_type,
            "category": category,
            "dataset": "foxclaw.scan",
            "id": event_id,
            "kind": kind,
            "module": "foxclaw",
            "provider": "foxclaw",
            "type": event_type_values,
        },
        "foxclaw": {
            "event_type": event_type,
            "profile": dict(profile),
            "scan": {
                "id": scan_id,
            },
            "schema_version": FOXCLAW_ECS_SCHEMA_VERSION,
        },
        "host": host_payload,
        "labels": {
            "foxclaw_event_type": event_type,
            "foxclaw_profile_id": str(profile["profile_id"]),
            "foxclaw_profile_uid": str(profile["profile_uid"]),
            "foxclaw_scan_id": scan_id,
            "foxclaw_severity": severity,
        },
        "message": message,
        "observer": {
            "name": "FoxClaw",
            "product": "FoxClaw",
            "type": "scanner",
            "vendor": "FoxClaw",
        },
    }


def _build_ecs_host(host: FleetHostMetadata) -> dict[str, object]:
    payload: dict[str, object] = {
        "architecture": host.architecture,
        "hostname": host.hostname,
        "id": host.host_id,
        "name": host.hostname,
        "os": {
            "family": _host_os_family(host.os_name),
            "full": f"{host.os_name} {host.os_version}".strip(),
            "kernel": host.os_release,
            "name": host.os_name,
            "platform": _host_os_platform(host.os_name),
            "type": _host_os_platform(host.os_name),
            "version": host.os_version,
        },
    }
    domain = _host_domain(host.fqdn, host.hostname)
    if domain is not None:
        payload["domain"] = domain
    return payload


def _host_domain(fqdn: str, hostname: str) -> str | None:
    if not fqdn or fqdn == hostname or "." not in fqdn:
        return None
    _, _, suffix = fqdn.partition(".")
    return suffix or None


def _host_os_platform(os_name: str) -> str:
    normalized = os_name.strip().lower()
    if normalized in {"darwin", "macos", "mac os"}:
        return "macos"
    if normalized.startswith("win"):
        return "windows"
    if normalized in {"linux", "freebsd", "openbsd", "netbsd"}:
        return normalized
    return normalized or "unknown"


def _host_os_family(os_name: str) -> str:
    platform_value = _host_os_platform(os_name)
    if platform_value in {"freebsd", "openbsd", "netbsd"}:
        return "unix"
    return platform_value


def _build_event_id(
    *,
    event_type: str,
    host_id: str,
    profile_id: str,
    timestamp: str,
    rule_id: str | None = None,
) -> str:
    parts = [
        f"event_type={event_type}",
        f"host.id={host_id}",
        f"profile.profile_id={profile_id}",
    ]
    if rule_id is not None:
        parts.append(f"rule.id={rule_id}")
    parts.extend(
        [
            f"timestamp={timestamp}",
            f"schema_version={FOXCLAW_ECS_SCHEMA_VERSION}",
        ]
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _build_scan_id(*, timestamp: str, host_id: str, profile_id: str) -> str:
    raw = "|".join(
        [
            f"timestamp={timestamp}",
            f"host.id={host_id}",
            f"profile.profile_id={profile_id}",
            f"schema_version={FOXCLAW_ECS_SCHEMA_VERSION}",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _severity_score(severity: str) -> int:
    return {
        "HIGH": 80,
        "MEDIUM": 50,
        "INFO": 20,
    }.get(severity, 20)


def _risk_score(priority: RiskPriority) -> int:
    return {
        "low": 25,
        "medium": 50,
        "high": 75,
        "critical": 100,
    }[priority]


def _log_level(severity: str) -> str:
    return {
        "HIGH": "error",
        "MEDIUM": "warning",
        "INFO": "info",
    }.get(severity, "info")


def _event_id_from_event(event: dict[str, object]) -> str:
    event_payload = event.get("event")
    if isinstance(event_payload, dict):
        event_id = event_payload.get("id")
        if isinstance(event_id, str) and event_id:
            return event_id
    return "<unknown>"


def _require_object_dict(value: object, *, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"Invalid ECS event: {field} must be an object.")
    return cast(dict[str, object], value)


def _validate_event(event: dict[str, object]) -> None:
    for field in _BASE_REQUIRED_FIELDS:
        value = event.get(field)
        if value is None or value == "":
            raise ValueError(f"Invalid ECS event: missing required field {field}.")

    timestamp = event["@timestamp"]
    if not isinstance(timestamp, str):
        raise ValueError("Invalid ECS event: @timestamp must be a string.")
    _parse_timestamp(timestamp)

    ecs_payload = event["ecs"]
    if not isinstance(ecs_payload, dict) or not ecs_payload.get("version"):
        raise ValueError("Invalid ECS event: ecs.version is required.")

    host_payload = event["host"]
    if not isinstance(host_payload, dict) or not host_payload.get("id") or not host_payload.get("name"):
        raise ValueError("Invalid ECS event: host.id and host.name are required.")

    event_payload = event["event"]
    if not isinstance(event_payload, dict):
        raise ValueError("Invalid ECS event: event object is required.")
    if not event_payload.get("id") or not event_payload.get("kind"):
        raise ValueError("Invalid ECS event: event.id and event.kind are required.")
    if not _is_non_empty_string_list(event_payload.get("category")):
        raise ValueError("Invalid ECS event: event.category must be a non-empty string list.")
    if not _is_non_empty_string_list(event_payload.get("type")):
        raise ValueError("Invalid ECS event: event.type must be a non-empty string list.")

    foxclaw_payload = event["foxclaw"]
    if not isinstance(foxclaw_payload, dict):
        raise ValueError("Invalid ECS event: foxclaw extension object is required.")
    profile_payload = foxclaw_payload.get("profile")
    if not isinstance(profile_payload, dict) or not profile_payload.get("profile_id") or not profile_payload.get("name"):
        raise ValueError("Invalid ECS event: foxclaw.profile.profile_id and name are required.")

    action = event_payload.get("action")
    if action == "foxclaw.finding":
        rule_payload = event.get("rule")
        if not isinstance(rule_payload, dict) or not rule_payload.get("id"):
            raise ValueError("Invalid ECS finding event: rule.id is required.")
        if "summary" in foxclaw_payload:
            raise ValueError("Invalid ECS finding event: foxclaw.summary must be omitted.")
    elif action == "foxclaw.scan.summary":
        if "rule" in event:
            raise ValueError("Invalid ECS summary event: rule must be omitted.")
        if "finding" in foxclaw_payload:
            raise ValueError("Invalid ECS summary event: foxclaw.finding must be omitted.")
    else:
        raise ValueError(f"Invalid ECS event action: {action}")


def _is_non_empty_string_list(value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    return all(isinstance(item, str) and item for item in value)


def _parse_timestamp(timestamp: str) -> None:
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid ECS event: @timestamp must be RFC3339/ISO8601 UTC.") from exc


def _format_timestamp(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    return normalized.isoformat().replace("+00:00", "Z")


def _finding_sort_key(finding: Finding) -> tuple[int, str, tuple[str, ...]]:
    return (
        SEVERITY_ORDER.get(finding.severity, 99),
        finding.id,
        tuple(finding.evidence),
    )
