"""Offline intelligence correlation for Firefox vulnerability posture."""

from __future__ import annotations

import configparser
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from foxclaw.intel.models import IntelCorrelationEvidence, IntelMatchedMozillaAdvisory
from foxclaw.intel.store import default_store_dir
from foxclaw.intel.versioning import normalize_version, version_matches_spec
from foxclaw.models import Finding, FindingSeverity, RiskPriority
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
_SEVERITY_SOURCE_PRECEDENCE: tuple[str, ...] = ("mozilla", "nvd", "cve_list")
_SEVERITY_BASE_PRIORITY: dict[FindingSeverity, RiskPriority] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "INFO": "low",
}
_RISK_PRIORITY_ORDER: dict[RiskPriority, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass(frozen=True, slots=True)
class _AdvisoryQueryResult:
    indexed_count: int
    matches: list[IntelMatchedMozillaAdvisory]


@dataclass(frozen=True, slots=True)
class _ExternalSeverityRecord:
    source_name: str
    severity: str | None = None
    reference_url: str | None = None


@dataclass(frozen=True, slots=True)
class _KevCatalogRecord:
    source_name: str
    vendor_project: str | None = None
    product: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    known_ransomware_campaign_use: str | None = None
    short_description: str | None = None
    reference_url: str | None = None


@dataclass(frozen=True, slots=True)
class _EpssScoreRecord:
    source_name: str
    score: float
    percentile: float | None = None
    reference_url: str | None = None


@dataclass(slots=True)
class _CveFeedEnrichment:
    nvd: list[_ExternalSeverityRecord] = field(default_factory=list)
    cve_list: list[_ExternalSeverityRecord] = field(default_factory=list)
    kev: list[_KevCatalogRecord] = field(default_factory=list)
    epss: list[_EpssScoreRecord] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _SeverityResolution:
    selected: FindingSeverity
    selected_source: str
    candidates: dict[str, list[FindingSeverity]]
    conflict: bool


@dataclass(frozen=True, slots=True)
class _RiskPriorityResolution:
    priority: RiskPriority
    factors: list[str]


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
    enrichment_by_cve = _load_cve_enrichment(
        store_dir=store_dir,
        snapshot_id=snapshot_id,
        cve_ids={_normalize_cve_id(item.cve_id) for item in advisories.matches if item.cve_id.strip()},
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
        enrichment_by_cve=enrichment_by_cve,
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
    except (OSError, configparser.Error):
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

    try:
        with sqlite3.connect(db_path) as connection:
            snapshot_row = connection.execute(
                "SELECT COUNT(*) FROM intel_snapshots WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchone()
            if snapshot_row is None or snapshot_row[0] == 0:
                raise ValueError(f"intel snapshot id not found: {snapshot_id}")

            if not _table_exists(connection, table_name="mozilla_advisories"):
                return _AdvisoryQueryResult(indexed_count=0, matches=[])
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
    except sqlite3.Error as exc:
        raise ValueError(f"intel store query failed: {db_path}: {exc}") from exc

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
                source_name=str(source_name),
                advisory_id=str(advisory_id),
                cve_id=str(cve_id),
                affected_versions=str(affected_versions),
                fixed_version=str(fixed_version) if fixed_version is not None else None,
                severity=str(severity) if severity is not None else None,
                reference_url=str(reference_url) if reference_url is not None else None,
            )
        )
    return _AdvisoryQueryResult(indexed_count=indexed_count, matches=matches)


def _load_cve_enrichment(
    *,
    store_dir: Path,
    snapshot_id: str,
    cve_ids: set[str],
) -> dict[str, _CveFeedEnrichment]:
    if not cve_ids:
        return {}

    db_path = store_dir / "intel.db"
    if not db_path.is_file():
        raise ValueError(f"intel store database not found: {db_path}")

    by_cve: dict[str, _CveFeedEnrichment] = {}

    try:
        with sqlite3.connect(db_path) as connection:
            if _table_exists(connection, table_name="nvd_cves"):
                rows = connection.execute(
                    """
                    SELECT cve_id, source_name, severity, reference_url
                    FROM nvd_cves
                    WHERE snapshot_id = ?
                    ORDER BY cve_id, source_name, severity, reference_url;
                    """,
                    (snapshot_id,),
                ).fetchall()
                for cve_id, source_name, severity, reference_url in rows:
                    normalized_cve = _normalize_cve_id(str(cve_id))
                    if normalized_cve not in cve_ids:
                        continue
                    bucket = by_cve.setdefault(normalized_cve, _CveFeedEnrichment())
                    bucket.nvd.append(
                        _ExternalSeverityRecord(
                            source_name=str(source_name),
                            severity=str(severity) if severity is not None else None,
                            reference_url=str(reference_url) if reference_url is not None else None,
                        )
                    )

            if _table_exists(connection, table_name="cve_list_records"):
                rows = connection.execute(
                    """
                    SELECT cve_id, source_name, severity, reference_url
                    FROM cve_list_records
                    WHERE snapshot_id = ?
                    ORDER BY cve_id, source_name, severity, reference_url;
                    """,
                    (snapshot_id,),
                ).fetchall()
                for cve_id, source_name, severity, reference_url in rows:
                    normalized_cve = _normalize_cve_id(str(cve_id))
                    if normalized_cve not in cve_ids:
                        continue
                    bucket = by_cve.setdefault(normalized_cve, _CveFeedEnrichment())
                    bucket.cve_list.append(
                        _ExternalSeverityRecord(
                            source_name=str(source_name),
                            severity=str(severity) if severity is not None else None,
                            reference_url=str(reference_url) if reference_url is not None else None,
                        )
                    )

            if _table_exists(connection, table_name="kev_catalog"):
                rows = connection.execute(
                    """
                    SELECT
                        cve_id,
                        source_name,
                        vendor_project,
                        product,
                        date_added,
                        due_date,
                        known_ransomware_campaign_use,
                        short_description,
                        reference_url
                    FROM kev_catalog
                    WHERE snapshot_id = ?
                    ORDER BY
                        cve_id,
                        source_name,
                        vendor_project,
                        product,
                        date_added,
                        due_date,
                        known_ransomware_campaign_use,
                        reference_url,
                        short_description;
                    """,
                    (snapshot_id,),
                ).fetchall()
                for (
                    cve_id,
                    source_name,
                    vendor_project,
                    product,
                    date_added,
                    due_date,
                    known_ransomware_campaign_use,
                    short_description,
                    reference_url,
                ) in rows:
                    normalized_cve = _normalize_cve_id(str(cve_id))
                    if normalized_cve not in cve_ids:
                        continue
                    bucket = by_cve.setdefault(normalized_cve, _CveFeedEnrichment())
                    bucket.kev.append(
                        _KevCatalogRecord(
                            source_name=str(source_name),
                            vendor_project=(
                                str(vendor_project) if vendor_project is not None else None
                            ),
                            product=str(product) if product is not None else None,
                            date_added=str(date_added) if date_added is not None else None,
                            due_date=str(due_date) if due_date is not None else None,
                            known_ransomware_campaign_use=(
                                str(known_ransomware_campaign_use)
                                if known_ransomware_campaign_use is not None
                                else None
                            ),
                            short_description=(
                                str(short_description) if short_description is not None else None
                            ),
                            reference_url=str(reference_url) if reference_url is not None else None,
                        )
                    )

            if _table_exists(connection, table_name="epss_scores"):
                rows = connection.execute(
                    """
                    SELECT cve_id, source_name, score, percentile, reference_url
                    FROM epss_scores
                    WHERE snapshot_id = ?
                    ORDER BY cve_id, source_name, score DESC, percentile DESC, reference_url;
                    """,
                    (snapshot_id,),
                ).fetchall()
                for cve_id, source_name, score, percentile, reference_url in rows:
                    normalized_cve = _normalize_cve_id(str(cve_id))
                    if normalized_cve not in cve_ids:
                        continue
                    bucket = by_cve.setdefault(normalized_cve, _CveFeedEnrichment())
                    bucket.epss.append(
                        _EpssScoreRecord(
                            source_name=str(source_name),
                            score=float(score),
                            percentile=float(percentile) if percentile is not None else None,
                            reference_url=str(reference_url) if reference_url is not None else None,
                        )
                    )
    except sqlite3.Error as exc:
        raise ValueError(f"intel store enrichment query failed: {db_path}: {exc}") from exc

    for enrichment in by_cve.values():
        enrichment.nvd.sort(
            key=lambda item: (
                item.source_name,
                item.severity or "",
                item.reference_url or "",
            )
        )
        enrichment.cve_list.sort(
            key=lambda item: (
                item.source_name,
                item.severity or "",
                item.reference_url or "",
            )
        )
        enrichment.kev.sort(
            key=lambda item: (
                item.source_name,
                item.vendor_project or "",
                item.product or "",
                item.date_added or "",
                item.due_date or "",
                item.known_ransomware_campaign_use or "",
                item.reference_url or "",
                item.short_description or "",
            )
        )
        enrichment.epss.sort(
            key=lambda item: (
                item.source_name,
                -item.score,
                -(item.percentile if item.percentile is not None else -1.0),
                item.reference_url or "",
            )
        )
    return by_cve


def _table_exists(connection: sqlite3.Connection, *, table_name: str) -> bool:
    row = connection.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?;",
        (table_name,),
    ).fetchone()
    return row is not None and int(row[0]) > 0


def _build_findings(
    *,
    snapshot_id: str,
    profile_version: str,
    matches: list[IntelMatchedMozillaAdvisory],
    enrichment_by_cve: dict[str, _CveFeedEnrichment],
) -> list[Finding]:
    by_cve: dict[str, list[IntelMatchedMozillaAdvisory]] = {}
    for match in matches:
        normalized_cve = _normalize_cve_id(match.cve_id)
        if not normalized_cve:
            continue
        by_cve.setdefault(normalized_cve, []).append(match)

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
        enrichment = enrichment_by_cve.get(cve_id, _CveFeedEnrichment())
        severity_resolution = _resolve_severity(grouped, enrichment)
        risk_resolution = _resolve_risk_priority(
            severity=severity_resolution.selected,
            enrichment=enrichment,
            severity_source=severity_resolution.selected_source,
        )
        findings.append(
            Finding(
                id=_build_finding_id(cve_id),
                title=f"Firefox version matches known vulnerability {cve_id}",
                severity=severity_resolution.selected,
                category="vulnerability_intel",
                rationale=_build_rationale(severity_resolution),
                recommendation=_build_recommendation(grouped),
                confidence="high",
                risk_priority=risk_resolution.priority,
                risk_factors=risk_resolution.factors,
                evidence=_build_evidence_lines(
                    snapshot_id=snapshot_id,
                    profile_version=profile_version,
                    cve_id=cve_id,
                    advisories=grouped,
                    enrichment=enrichment,
                    severity_resolution=severity_resolution,
                    risk_resolution=risk_resolution,
                ),
            )
        )
    return sort_findings(findings)


def _resolve_severity(
    advisories: list[IntelMatchedMozillaAdvisory],
    enrichment: _CveFeedEnrichment,
) -> _SeverityResolution:
    candidates = {
        "mozilla": _collect_severity_candidates([item.severity for item in advisories]),
        "nvd": _collect_severity_candidates([item.severity for item in enrichment.nvd]),
        "cve_list": _collect_severity_candidates([item.severity for item in enrichment.cve_list]),
    }

    selected: FindingSeverity = "MEDIUM"
    selected_source = "default"
    for source_name in _SEVERITY_SOURCE_PRECEDENCE:
        source_candidates = candidates[source_name]
        if not source_candidates:
            continue
        selected = _select_highest_severity(source_candidates)
        selected_source = source_name
        break

    all_candidates = {
        severity
        for source_candidates in candidates.values()
        for severity in source_candidates
    }
    return _SeverityResolution(
        selected=selected,
        selected_source=selected_source,
        candidates=candidates,
        conflict=len(all_candidates) > 1,
    )


def _collect_severity_candidates(raw_values: list[str | None]) -> list[FindingSeverity]:
    if not raw_values:
        return []

    mapped: set[FindingSeverity] = set()
    for raw in raw_values:
        mapped.add(_map_severity(raw))
    return sorted(mapped, key=lambda item: _SEVERITY_ORDER[item])


def _map_severity(raw: str | None) -> FindingSeverity:
    return _CVSS_TO_FINDING.get((raw or "").strip().lower(), "MEDIUM")


def _select_highest_severity(candidates: list[FindingSeverity]) -> FindingSeverity:
    return sorted(set(candidates), key=lambda item: _SEVERITY_ORDER[item])[0]


def _build_rationale(severity_resolution: _SeverityResolution) -> str:
    base = (
        "The local Firefox version satisfies an affected-version range from the pinned "
        "intelligence snapshot."
    )
    policy = (
        "Severity is resolved with deterministic source precedence "
        "(mozilla > nvd > cve_list)."
    )
    if not severity_resolution.conflict:
        return f"{base} {policy}"
    return (
        f"{base} {policy} Severity signals conflicted across sources and were resolved "
        "using that precedence policy."
    )


def _resolve_risk_priority(
    *,
    severity: FindingSeverity,
    enrichment: _CveFeedEnrichment,
    severity_source: str,
) -> _RiskPriorityResolution:
    priority = _SEVERITY_BASE_PRIORITY[severity]
    factors = [f"severity:{severity.lower()}", f"severity_source:{severity_source}"]

    if enrichment.kev:
        priority = "critical"
        factors.append("kev_listed")

    max_epss = _max_epss_score(enrichment.epss)
    if max_epss is not None:
        factors.append(f"epss_score:{max_epss:.4f}")
        if max_epss >= 0.9:
            priority = _max_risk_priority(priority, "high")
            factors.append("epss_bucket:very_high")
        elif max_epss >= 0.7:
            priority = _max_risk_priority(priority, "medium")
            factors.append("epss_bucket:high")

    return _RiskPriorityResolution(priority=priority, factors=sorted(factors))


def _max_epss_score(records: list[_EpssScoreRecord]) -> float | None:
    if not records:
        return None
    return max(record.score for record in records)


def _max_risk_priority(current: RiskPriority, minimum: RiskPriority) -> RiskPriority:
    if _RISK_PRIORITY_ORDER[current] >= _RISK_PRIORITY_ORDER[minimum]:
        return current
    return minimum


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
    cve_id: str,
    advisories: list[IntelMatchedMozillaAdvisory],
    enrichment: _CveFeedEnrichment,
    severity_resolution: _SeverityResolution,
    risk_resolution: _RiskPriorityResolution,
) -> list[str]:
    evidence = [
        f"intel_snapshot_id={snapshot_id}",
        f"profile_firefox_version={profile_version}",
        f"cve_id={cve_id}",
    ]
    provenance_sources = _collect_provenance_sources(advisories, enrichment)
    if provenance_sources:
        evidence.append(f"intel_provenance_sources={','.join(provenance_sources)}")
    evidence.append(
        "severity_resolution="
        f"selected:{severity_resolution.selected},"
        f"source:{severity_resolution.selected_source},"
        "policy:mozilla>nvd>cve_list"
    )
    evidence.append(
        f"severity_conflict={int(severity_resolution.conflict)}, "
        f"candidates={_format_severity_candidates(severity_resolution.candidates)}"
    )
    evidence.append(f"risk_priority={risk_resolution.priority}")
    evidence.append(f"risk_factors={','.join(risk_resolution.factors)}")

    for advisory in advisories:
        line = (
            f"mozilla:{advisory.source_name}:{advisory.advisory_id}: "
            f"affected={advisory.affected_versions}, "
            f"fixed={advisory.fixed_version or 'unknown'}, "
            f"severity={advisory.severity or 'unknown'}"
        )
        evidence.append(line)
        if advisory.reference_url:
            evidence.append(
                f"mozilla:{advisory.source_name}:{advisory.advisory_id}: "
                f"url={advisory.reference_url}"
            )

    for nvd_record in enrichment.nvd:
        evidence.append(
            f"nvd:{nvd_record.source_name}:severity={nvd_record.severity or 'unknown'}"
        )
        if nvd_record.reference_url:
            evidence.append(f"nvd:{nvd_record.source_name}:url={nvd_record.reference_url}")

    for cve_list_record in enrichment.cve_list:
        evidence.append(
            f"cve_list:{cve_list_record.source_name}:"
            f"severity={cve_list_record.severity or 'unknown'}"
        )
        if cve_list_record.reference_url:
            evidence.append(
                f"cve_list:{cve_list_record.source_name}:url={cve_list_record.reference_url}"
            )

    for kev_record in enrichment.kev:
        evidence.append(
            "kev:"
            f"{kev_record.source_name}:listed=1,"
            f"vendor={kev_record.vendor_project or 'unknown'},"
            f"product={kev_record.product or 'unknown'},"
            f"due_date={kev_record.due_date or 'unknown'},"
            f"ransomware_use={kev_record.known_ransomware_campaign_use or 'unknown'}"
        )
        if kev_record.reference_url:
            evidence.append(f"kev:{kev_record.source_name}:url={kev_record.reference_url}")

    for epss_record in enrichment.epss:
        percentile = (
            f"{epss_record.percentile:.4f}"
            if epss_record.percentile is not None
            else "unknown"
        )
        evidence.append(
            f"epss:{epss_record.source_name}:score={epss_record.score:.4f},"
            f"percentile={percentile}"
        )
        if epss_record.reference_url:
            evidence.append(f"epss:{epss_record.source_name}:url={epss_record.reference_url}")
    return evidence


def _collect_provenance_sources(
    advisories: list[IntelMatchedMozillaAdvisory],
    enrichment: _CveFeedEnrichment,
) -> list[str]:
    sources = {item.source_name for item in advisories}
    sources.update(item.source_name for item in enrichment.nvd)
    sources.update(item.source_name for item in enrichment.cve_list)
    sources.update(item.source_name for item in enrichment.kev)
    sources.update(item.source_name for item in enrichment.epss)
    return sorted(source for source in sources if source.strip())


def _format_severity_candidates(candidates: dict[str, list[FindingSeverity]]) -> str:
    parts: list[str] = []
    for source_name in _SEVERITY_SOURCE_PRECEDENCE:
        levels = candidates.get(source_name, [])
        if not levels:
            continue
        parts.append(f"{source_name}:{'|'.join(levels)}")
    if not parts:
        return "none"
    return ";".join(parts)


def _normalize_cve_id(cve_id: str) -> str:
    return cve_id.strip().upper()
