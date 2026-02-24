"""Deterministic snapshot diff helpers."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from foxclaw.models import (
    Finding,
    ScanSnapshot,
    ScanSnapshotDiff,
    SnapshotDiffSummary,
    SnapshotFindingChange,
    SnapshotMetadata,
)

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def load_scan_snapshot(path: Path) -> ScanSnapshot:
    """Load and validate a scan snapshot file."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise OSError(f"Unable to read snapshot file: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Snapshot file is not valid JSON: {path}: {exc}") from exc

    try:
        return ScanSnapshot.model_validate(payload)
    except ValueError as exc:
        raise ValueError(f"Snapshot validation failed: {path}: {exc}") from exc


def build_scan_snapshot_diff(before: ScanSnapshot, after: ScanSnapshot) -> ScanSnapshotDiff:
    """Build deterministic diff object between two snapshots."""
    before_by_id = _findings_by_id(before.findings, label="before")
    after_by_id = _findings_by_id(after.findings, label="after")

    before_ids = set(before_by_id.keys())
    after_ids = set(after_by_id.keys())

    added_findings = _sort_findings(
        [after_by_id[rule_id] for rule_id in sorted(after_ids - before_ids)]
    )
    removed_findings = _sort_findings(
        [before_by_id[rule_id] for rule_id in sorted(before_ids - after_ids)]
    )

    changed_rule_ids = sorted(
        rule_id
        for rule_id in (before_ids & after_ids)
        if _finding_key(before_by_id[rule_id]) != _finding_key(after_by_id[rule_id])
    )
    changed_findings = [
        SnapshotFindingChange(
            rule_id=rule_id,
            before=before_by_id[rule_id],
            after=after_by_id[rule_id],
        )
        for rule_id in changed_rule_ids
    ]

    summary = SnapshotDiffSummary(
        drift_detected=bool(added_findings or removed_findings or changed_findings),
        before_findings_total=len(before.findings),
        after_findings_total=len(after.findings),
        before_findings_high_count=before.summary.findings_high_count,
        after_findings_high_count=after.summary.findings_high_count,
        before_findings_medium_count=before.summary.findings_medium_count,
        after_findings_medium_count=after.summary.findings_medium_count,
        before_findings_info_count=before.summary.findings_info_count,
        after_findings_info_count=after.summary.findings_info_count,
        added_findings_count=len(added_findings),
        removed_findings_count=len(removed_findings),
        changed_findings_count=len(changed_findings),
    )
    return ScanSnapshotDiff(
        before=_snapshot_metadata(before),
        after=_snapshot_metadata(after),
        summary=summary,
        added_findings=added_findings,
        removed_findings=removed_findings,
        changed_findings=changed_findings,
    )


def render_snapshot_diff_json(diff: ScanSnapshotDiff) -> str:
    """Render deterministic JSON snapshot diff payload."""
    return json.dumps(diff.model_dump(mode="json"), indent=2, sort_keys=True)


def render_snapshot_diff_summary(console: Console, diff: ScanSnapshotDiff) -> None:
    """Render terminal summary for snapshot drift."""
    summary = diff.summary
    table = Table(title="Snapshot Drift Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Drift detected", "yes" if summary.drift_detected else "no")
    table.add_row("Findings before", str(summary.before_findings_total))
    table.add_row("Findings after", str(summary.after_findings_total))
    table.add_row("Added findings", str(summary.added_findings_count))
    table.add_row("Removed findings", str(summary.removed_findings_count))
    table.add_row("Changed findings", str(summary.changed_findings_count))
    console.print(table)


def _snapshot_metadata(snapshot: ScanSnapshot) -> SnapshotMetadata:
    return SnapshotMetadata(
        snapshot_schema_version=snapshot.snapshot_schema_version,
        evidence_schema_version=snapshot.evidence_schema_version,
        profile=snapshot.profile,
        ruleset=snapshot.ruleset,
        intel_snapshot_id=snapshot.intel.snapshot_id,
    )


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.id,
            tuple(finding.evidence),
        ),
    )


def _findings_by_id(findings: list[Finding], *, label: str) -> dict[str, Finding]:
    indexed: dict[str, Finding] = {}
    duplicates: list[str] = []
    for finding in findings:
        if finding.id in indexed:
            duplicates.append(finding.id)
            continue
        indexed[finding.id] = finding
    if duplicates:
        duplicate_ids = ", ".join(sorted(set(duplicates)))
        raise ValueError(f"{label} snapshot contains duplicate finding ids: {duplicate_ids}")
    return indexed


def _finding_key(finding: Finding) -> tuple[str, str, tuple[str, ...]]:
    return (finding.id, finding.severity, tuple(finding.evidence))
