"""Offline intelligence correlation for Firefox vulnerability posture."""

from __future__ import annotations

import configparser
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from foxclaw.intel.models import IntelCorrelationEvidence, IntelMatchedMozillaAdvisory
from foxclaw.intel.store import default_store_dir
from foxclaw.intel.versioning import normalize_version, version_matches_spec
from foxclaw.models import Finding, FindingSeverity
from foxclaw.rules.engine import sort_findings

_SEVERITY_ORDER: dict[FindingSeverity, int] = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
_CVSS_TO_FINDING: dict[str, FindingSeverity] = {
    "critical": "HIGH",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "INFO",
    "info": "INFO",
}


@dataclass(frozen=True, slots=True)
class _AdvisoryQueryResult:
    indexed_count: int
    matches: list[IntelMatchedMozillaAdvisory]


def correlate_firefox_vulnerability_intel(
    *,
    profile_dir: Path,
    intel_store_dir: Path | None,
    intel_snapshot_id: str | None,
) -> tuple[IntelCorrelationEvidence, list[Finding]]:
    """Correlate profile Firefox version against indexed advisory records."""
    if intel_store_dir is None and intel_snapshot_id is None:
        return IntelCorrelationEvidence(), []

    store_dir = (intel_store_dir or default_store_dir()).expanduser().resolve(strict=False)
    snapshot_id = _resolve_snapshot_id(store_dir=store_dir, intel_snapshot_id=intel_snapshot_id)
    profile_version = read_profile_firefox_version(profile_dir)
    if profile_version is None:
        evidence = IntelCorrelationEvidence(
            enabled=True,
            store_dir=str(store_dir),
            snapshot_id=snapshot_id,
            error="compatibility.ini LastVersion was not available",
        )
        return evidence, []

    advisories = _load_mozilla_advisories(
        store_dir=store_dir,
        snapshot_id=snapshot_id,
        profile_version=profile_version,
    )
    evidence = IntelCorrelationEvidence(
        enabled=True,
        store_dir=str(store_dir),
        snapshot_id=snapshot_id,
        profile_firefox_version=profile_version,
        advisories_indexed=advisories.indexed_count,
        matched_advisories=advisories.matches,
    )
    findings = _build_findings(
        snapshot_id=snapshot_id,
        profile_version=profile_version,
        matches=advisories.matches,
    )
    return evidence, findings


def read_profile_firefox_version(profile_dir: Path) -> str | None:
    """Read normalized Firefox version from compatibility.ini LastVersion."""
    compatibility_path = profile_dir / "compatibility.ini"
    if not compatibility_path.is_file():
        return None

    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(compatibility_path, encoding="utf-8")
    except OSError:
        return None

    raw = parser.get("Compatibility", "LastVersion", fallback="").strip()
    if not raw:
        return None

    return normalize_version(raw)


def _resolve_snapshot_id(*, store_dir: Path, intel_snapshot_id: str | None) -> str:
    if intel_snapshot_id is not None and intel_snapshot_id.strip().lower() != "latest":
        return intel_snapshot_id.strip()

    pointer_path = store_dir / "latest.json"
    try:
        payload = json.loads(pointer_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(
            f"unable to resolve latest intel snapshot pointer at {pointer_path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"intel latest pointer is invalid JSON: {pointer_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"intel latest pointer has invalid payload: {pointer_path}")
    raw_snapshot_id = payload.get("snapshot_id")
    if not isinstance(raw_snapshot_id, str) or not raw_snapshot_id.strip():
        raise ValueError(f"intel latest pointer missing snapshot_id: {pointer_path}")
    return raw_snapshot_id.strip()


def _load_mozilla_advisories(
    *,
    store_dir: Path,
    snapshot_id: str,
    profile_version: str,
) -> _AdvisoryQueryResult:
    db_path = store_dir / "intel.db"
    if not db_path.is_file():
        raise ValueError(f"intel store database not found: {db_path}")

    with sqlite3.connect(db_path) as connection:
        snapshot_row = connection.execute(
            "SELECT COUNT(*) FROM intel_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        if snapshot_row is None or snapshot_row[0] == 0:
            raise ValueError(f"intel snapshot id not found: {snapshot_id}")

        _require_table(connection, table_name="mozilla_advisories")
        indexed_row = connection.execute(
            "SELECT COUNT(*) FROM mozilla_advisories WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        indexed_count = int(indexed_row[0]) if indexed_row is not None else 0

        rows = connection.execute(
            """
            SELECT source_name, advisory_id, cve_id, affected_versions, fixed_version, severity, reference_url
            FROM mozilla_advisories
            WHERE snapshot_id = ?
            ORDER BY cve_id, advisory_id, source_name, affected_versions, fixed_version;
            """,
            (snapshot_id,),
        ).fetchall()

    matches: list[IntelMatchedMozillaAdvisory] = []
    for (
        source_name,
        advisory_id,
        cve_id,
        affected_versions,
        fixed_version,
        severity,
        reference_url,
    ) in rows:
        if not version_matches_spec(version=profile_version, spec=affected_versions):
            continue
        matches.append(
            IntelMatchedMozillaAdvisory(
                source_name=source_name,
                advisory_id=advisory_id,
                cve_id=cve_id,
                affected_versions=affected_versions,
                fixed_version=fixed_version,
                severity=severity,
                reference_url=reference_url,
            )
        )
    return _AdvisoryQueryResult(indexed_count=indexed_count, matches=matches)


def _require_table(connection: sqlite3.Connection, *, table_name: str) -> None:
    row = connection.execute(
        """
        SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?;
        """,
        (table_name,),
    ).fetchone()
    if row is None or row[0] == 0:
        raise ValueError(
            f"intel store is missing required table '{table_name}'; run `foxclaw intel sync` again"
        )


def _build_findings(
    *,
    snapshot_id: str,
    profile_version: str,
    matches: list[IntelMatchedMozillaAdvisory],
) -> list[Finding]:
    by_cve: dict[str, list[IntelMatchedMozillaAdvisory]] = {}
    for match in matches:
        by_cve.setdefault(match.cve_id, []).append(match)

    findings: list[Finding] = []
    for cve_id in sorted(by_cve):
        grouped = sorted(
            by_cve[cve_id],
            key=lambda item: (
                item.source_name,
                item.advisory_id,
                item.affected_versions,
                item.fixed_version or "",
                item.reference_url or "",
            ),
        )
        severity = _select_severity(grouped)
        findings.append(
            Finding(
                id=_build_finding_id(cve_id),
                title=f"Firefox version matches known vulnerability {cve_id}",
                severity=severity,
                category="vulnerability_intel",
                rationale=(
                    "The local Firefox version satisfies an affected-version range "
                    "from the pinned intelligence snapshot."
                ),
                recommendation=_build_recommendation(grouped),
                confidence="high",
                evidence=_build_evidence_lines(
                    snapshot_id=snapshot_id,
                    profile_version=profile_version,
                    advisories=grouped,
                ),
            )
        )
    return sort_findings(findings)


def _select_severity(advisories: list[IntelMatchedMozillaAdvisory]) -> FindingSeverity:
    severities = [
        _CVSS_TO_FINDING.get((advisory.severity or "").strip().lower(), "MEDIUM")
        for advisory in advisories
    ]
    return sorted(set(severities), key=lambda item: _SEVERITY_ORDER[item])[0]


def _build_finding_id(cve_id: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "-", cve_id.strip().upper()).strip("-")
    if not normalized:
        normalized = "UNKNOWN"
    return f"FC-INTEL-{normalized}"


def _build_recommendation(advisories: list[IntelMatchedMozillaAdvisory]) -> str:
    fixed_versions = sorted(
        {item.fixed_version for item in advisories if item.fixed_version},
        key=str,
    )
    if fixed_versions:
        joined = ", ".join(fixed_versions)
        return (
            "Upgrade Firefox to a release that includes fixes for this CVE; "
            f"reported fixed version(s): {joined}."
        )
    return "Upgrade Firefox to a current patched release and verify advisory details."


def _build_evidence_lines(
    *,
    snapshot_id: str,
    profile_version: str,
    advisories: list[IntelMatchedMozillaAdvisory],
) -> list[str]:
    evidence = [
        f"intel_snapshot_id={snapshot_id}",
        f"profile_firefox_version={profile_version}",
    ]
    for advisory in advisories:
        line = (
            f"{advisory.source_name}:{advisory.advisory_id}: "
            f"affected={advisory.affected_versions}, "
            f"fixed={advisory.fixed_version or 'unknown'}, "
            f"severity={advisory.severity or 'unknown'}"
        )
        evidence.append(line)
        if advisory.reference_url:
            evidence.append(f"{advisory.source_name}:{advisory.advisory_id}: url={advisory.reference_url}")
    return evidence
