"""Suppression policy loading and finding filtering."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path

import yaml
from pydantic import ValidationError

from foxclaw.models import (
    AppliedSuppression,
    Finding,
    SuppressionEntry,
    SuppressionEvidence,
    SuppressionPolicy,
)


@dataclass(frozen=True, slots=True)
class _SuppressionSource:
    source_path: Path
    entry: SuppressionEntry


def apply_suppressions(
    findings: list[Finding],
    *,
    profile_path: Path,
    suppression_paths: list[Path] | None,
    now: datetime | None = None,
) -> tuple[list[Finding], SuppressionEvidence]:
    """Apply suppression policies and return remaining findings + suppression telemetry."""
    if not suppression_paths:
        return findings, SuppressionEvidence()

    resolved_now = (now or datetime.now(UTC)).astimezone(UTC)
    source_paths = sorted(
        {
            path.expanduser().resolve(strict=False).as_posix()
            for path in suppression_paths
        }
    )

    source_entries, legacy_count = _load_suppression_sources(suppression_paths)
    evidence = SuppressionEvidence(
        source_paths=source_paths,
        legacy_schema_count=legacy_count,
    )

    active_sources: list[_SuppressionSource] = []
    for source in source_entries:
        if source.entry.expires_at.astimezone(UTC) < resolved_now:
            evidence.expired.append(
                AppliedSuppression(
                    id=source.entry.id,
                    rule_id=source.entry.rule_id,
                    owner=source.entry.owner,
                    reason=source.entry.reason,
                    expires_at=source.entry.expires_at.astimezone(UTC),
                    source_path=source.source_path.as_posix(),
                    approval=source.entry.approval,
                )
            )
            continue
        active_sources.append(source)

    remaining: list[Finding] = []
    normalized_profile_path = profile_path.expanduser().resolve(strict=False).as_posix()
    for finding in findings:
        match = _match_suppression(
            finding=finding,
            profile_path=normalized_profile_path,
            sources=active_sources,
        )
        if match is None:
            remaining.append(finding)
            continue

        evidence.applied.append(match)

        # Governance tracing
        evidence.applied_by_owner[match.owner] = evidence.applied_by_owner.get(match.owner, 0) + 1
        if match.approval is not None:
            approver = match.approval.approved_by
            evidence.applied_by_approver[approver] = evidence.applied_by_approver.get(approver, 0) + 1

        delta = match.expires_at - resolved_now
        if 0 <= delta.days <= 30:
            evidence.expiring_within_30d.append(match)

    return remaining, evidence


def _load_suppression_sources(paths: list[Path]) -> tuple[list[_SuppressionSource], int]:
    deduped_paths: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.expanduser().resolve(strict=False)
        if resolved in seen:
            continue
        deduped_paths.append(resolved)
        seen.add(resolved)

    loaded: list[_SuppressionSource] = []
    legacy_count: int = 0
    for path in deduped_paths:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise OSError(f"Unable to read suppression file: {path}: {exc}") from exc

        try:
            payload = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError(f"Unable to parse suppression YAML: {path}: {exc}") from exc

        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise ValueError(f"Suppression file must be a YAML object: {path}")

        try:
            policy = SuppressionPolicy.model_validate(payload)
        except ValidationError as exc:
            raise ValueError(f"Suppression policy validation failed: {path}: {exc}") from exc

        if policy.schema_version not in ("1.0.0", "1.1.0"):
            raise ValueError(f"Unsupported suppression schema_version '{policy.schema_version}': {path}")
        if policy.schema_version == "1.0.0":
            legacy_count += 1

        for index, entry in enumerate(policy.suppressions):
            normalized = _normalize_entry(entry, source_path=path, index=index, schema_version=policy.schema_version)
            loaded.append(_SuppressionSource(source_path=path, entry=normalized))

    # Deterministic matching precedence: path, rule id, then suppression id.
    loaded.sort(
        key=lambda item: (
            item.source_path.as_posix(),
            item.entry.rule_id,
            item.entry.id or "",
            item.entry.scope.profile_glob,
            item.entry.scope.evidence_contains or "",
        )
    )
    return loaded, legacy_count


def _normalize_entry(
    entry: SuppressionEntry, *, source_path: Path, index: int, schema_version: str
) -> SuppressionEntry:
    prefix = f"Suppression policy validation failed: {source_path}: suppressions[{index}]"

    if not entry.rule_id.strip():
        raise ValueError(f"{prefix}.rule_id cannot be empty")
    if not entry.owner.strip():
        raise ValueError(f"{prefix}.owner cannot be empty")
    if not entry.reason.strip():
        raise ValueError(f"{prefix}.reason cannot be empty")
    if not entry.scope.profile_glob.strip():
        raise ValueError(f"{prefix}.scope.profile_glob cannot be empty")

    if entry.expires_at.tzinfo is None or entry.expires_at.utcoffset() is None:
        raise ValueError(f"{prefix}.expires_at must include timezone offset")

    # Governance validation for schema 1.1.0
    if schema_version == "1.1.0":
        if entry.approval is None:
            raise ValueError(f"{prefix}.approval is required for schema_version 1.1.0")

        app = entry.approval
        if not app.requested_by.strip():
            raise ValueError(f"{prefix}.approval.requested_by cannot be empty")
        if not app.approved_by.strip():
            raise ValueError(f"{prefix}.approval.approved_by cannot be empty")
        if not app.ticket.strip():
            raise ValueError(f"{prefix}.approval.ticket cannot be empty")

        if app.requested_at.tzinfo is None or app.requested_at.utcoffset() is None:
            raise ValueError(f"{prefix}.approval.requested_at must include timezone offset")
        if app.approved_at.tzinfo is None or app.approved_at.utcoffset() is None:
            raise ValueError(f"{prefix}.approval.approved_at must include timezone offset")

        req_utc = app.requested_at.astimezone(UTC)
        app_utc = app.approved_at.astimezone(UTC)
        exp_utc = entry.expires_at.astimezone(UTC)

        if req_utc > app_utc:
            raise ValueError(f"{prefix}: requested_at ({req_utc}) must be <= approved_at ({app_utc})")
        if app_utc >= exp_utc:
            raise ValueError(f"{prefix}: approved_at ({app_utc}) must be < expires_at ({exp_utc})")

    normalized_scope = entry.scope.model_copy(
        update={
            "profile_glob": entry.scope.profile_glob.strip(),
            "evidence_contains": (
                entry.scope.evidence_contains.strip()
                if entry.scope.evidence_contains and entry.scope.evidence_contains.strip()
                else None
            ),
        }
    )
    return entry.model_copy(
        update={
            "rule_id": entry.rule_id.strip(),
            "owner": entry.owner.strip(),
            "reason": entry.reason.strip(),
            "expires_at": entry.expires_at.astimezone(UTC),
            "scope": normalized_scope,
        }
    )


def _match_suppression(
    *,
    finding: Finding,
    profile_path: str,
    sources: list[_SuppressionSource],
) -> AppliedSuppression | None:
    for source in sources:
        entry = source.entry
        if finding.id != entry.rule_id:
            continue
        if not fnmatch(profile_path, entry.scope.profile_glob):
            continue

        evidence_match: str | None = None
        if entry.scope.evidence_contains is not None:
            if not any(entry.scope.evidence_contains in line for line in finding.evidence):
                continue
            evidence_match = entry.scope.evidence_contains

        return AppliedSuppression(
            id=entry.id,
            rule_id=entry.rule_id,
            owner=entry.owner,
            reason=entry.reason,
            expires_at=entry.expires_at,
            source_path=source.source_path.as_posix(),
            evidence_match=evidence_match,
            approval=entry.approval,
        )

    return None
