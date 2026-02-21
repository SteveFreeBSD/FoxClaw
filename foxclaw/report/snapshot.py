"""Deterministic snapshot rendering helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from foxclaw.models import (
    EvidenceBundle,
    ScanSnapshot,
    SnapshotRulesetMetadata,
)

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def render_scan_snapshot(
    bundle: EvidenceBundle,
    *,
    ruleset_path: Path,
    ruleset_name: str,
    ruleset_version: str,
    repo_root: Path | None = None,
) -> str:
    """Render a deterministic JSON snapshot payload."""
    payload = build_scan_snapshot(
        bundle,
        ruleset_path=ruleset_path,
        ruleset_name=ruleset_name,
        ruleset_version=ruleset_version,
        repo_root=repo_root,
    )
    return json.dumps(payload, indent=2, sort_keys=True)


def build_scan_snapshot(
    bundle: EvidenceBundle,
    *,
    ruleset_path: Path,
    ruleset_name: str,
    ruleset_version: str,
    repo_root: Path | None = None,
) -> dict[str, object]:
    """Build deterministic snapshot object for baseline and diff workflows."""
    resolved_repo_root = (repo_root or Path.cwd()).expanduser().resolve(strict=False)
    resolved_ruleset_path = ruleset_path.expanduser().resolve(strict=False)
    ruleset_sha256 = hashlib.sha256(resolved_ruleset_path.read_bytes()).hexdigest()

    findings = sorted(
        bundle.findings,
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.id,
            tuple(finding.evidence),
        ),
    )
    high_findings = sorted({finding.id for finding in findings if finding.severity == "HIGH"})

    normalized_profile = bundle.profile.model_copy(
        update={
            "path": _normalize_output_path(
                Path(bundle.profile.path),
                repo_root=resolved_repo_root,
            )
        }
    )
    snapshot = ScanSnapshot(
        evidence_schema_version=bundle.schema_version,
        profile=normalized_profile,
        ruleset=SnapshotRulesetMetadata(
            name=ruleset_name,
            version=ruleset_version,
            path=_normalize_output_path(resolved_ruleset_path, repo_root=resolved_repo_root),
            sha256=ruleset_sha256,
        ),
        intel=bundle.intel,
        summary=bundle.summary,
        high_findings=high_findings,
        findings=findings,
    )
    return snapshot.model_dump(mode="json")


def _normalize_output_path(path: Path, *, repo_root: Path) -> str:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        return candidate.as_posix()

    resolved_path = candidate.resolve(strict=False)
    try:
        relative = resolved_path.relative_to(repo_root)
    except ValueError:
        return resolved_path.as_posix()
    relative_text = relative.as_posix()
    return relative_text if relative_text else "."
