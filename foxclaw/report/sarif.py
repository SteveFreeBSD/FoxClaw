"""SARIF 2.1.0 rendering helpers for FoxClaw findings."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

from foxclaw import __version__
from foxclaw.models import SEVERITY_ORDER, EvidenceBundle, Finding

SARIF_SCHEMA_URL = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
_SEVERITY_TO_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "INFO": "note"}
_SEVERITY_TO_SECURITY_SCORE = {"HIGH": "8.9", "MEDIUM": "5.0", "INFO": "1.0"}
_FILE_URI_RE = re.compile(r"file://[^\s,;()]+")
_PATH_RE = re.compile(r"/[^\s,;()]+")
_LIKELY_FILE_SUFFIXES = (".db", ".sqlite", ".sqlite-wal", ".sqlite-shm", ".json", ".js")


def render_scan_sarif(bundle: EvidenceBundle, *, deterministic: bool = False) -> str:
    """Render a deterministic SARIF payload for scan findings."""
    payload = build_scan_sarif(bundle, deterministic=deterministic)
    return json.dumps(payload, indent=2, sort_keys=True)


def build_scan_sarif(
    bundle: EvidenceBundle, *, repo_root: Path | None = None, deterministic: bool = False
) -> dict[str, object]:
    """Build SARIF object for FoxClaw findings."""
    resolved_repo_root = (repo_root or Path.cwd()).expanduser().resolve(strict=False)
    profile_root = Path(bundle.profile.path).expanduser()
    findings = sorted(
        bundle.findings,
        key=lambda item: (SEVERITY_ORDER[item.severity], item.id, tuple(item.evidence)),
    )
    rules, rule_indices = _build_rules(findings)
    results = [
        _finding_to_result(
            finding,
            profile_root=profile_root,
            repo_root=resolved_repo_root,
            rule_index=rule_indices[finding.id],
            deterministic=deterministic,
        )
        for finding in findings
    ]

    run_properties = {}
    if bundle.bundle_provenance:
        run_properties["bundleProvenance"] = bundle.bundle_provenance.model_dump(mode="json")

    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "FoxClaw",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": rules,
            }
        },
        "results": results,
    }

    if run_properties:
        run["properties"] = run_properties

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def _build_rules(findings: list[Finding]) -> tuple[list[dict[str, object]], dict[str, int]]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped.setdefault(finding.id, finding)

    rules: list[dict[str, object]] = []
    rule_indices: dict[str, int] = {}
    for rule_id in sorted(deduped):
        finding = deduped[rule_id]
        rule_indices[rule_id] = len(rules)
        rules.append(
            {
                "id": finding.id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.rationale},
                "help": {"text": finding.recommendation},
                "helpUri": _rule_help_uri(finding.id),
                "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[finding.severity]},
                "properties": {
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "foxclawSeverity": finding.severity,
                    "security-severity": _SEVERITY_TO_SECURITY_SCORE[finding.severity],
                    "tags": _rule_tags(finding),
                },
            }
        )
    return rules, rule_indices


def _finding_to_result(
    finding: Finding, *, profile_root: Path, repo_root: Path, rule_index: int, deterministic: bool
) -> dict[str, object]:
    evidence_lines = [
        _normalize_evidence_line(
            line, profile_root=profile_root, repo_root=repo_root, deterministic=deterministic
        )
        for line in finding.evidence
    ]
    artifact_uri = _find_artifact_uri(
        evidence_lines,
        profile_root=profile_root,
        repo_root=repo_root,
        deterministic=deterministic,
    )
    if not evidence_lines:
        evidence_lines = ["No additional evidence."]
    evidence_text = " | ".join(evidence_lines)

    properties: dict[str, object] = {
        "category": finding.category,
        "confidence": finding.confidence,
        "foxclawSeverity": finding.severity,
        "security-severity": _SEVERITY_TO_SECURITY_SCORE[finding.severity],
        "tags": _rule_tags(finding),
        "evidence": evidence_lines,
    }
    if finding.risk_priority is not None:
        properties["riskPriority"] = finding.risk_priority
    if finding.risk_factors:
        properties["riskFactors"] = finding.risk_factors

    return {
        "ruleId": finding.id,
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": f"{finding.title}: {evidence_text}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                    }
                }
            }
        ],
        "properties": properties,
        "partialFingerprints": _build_partial_fingerprints(
            finding=finding,
            artifact_uri=artifact_uri,
            evidence_lines=evidence_lines,
        ),
    }


def _find_artifact_uri(
    evidence: list[str], *, profile_root: Path, repo_root: Path, deterministic: bool
) -> str:
    for line in evidence:
        artifact_uri = _extract_artifact_uri(
            line,
            profile_root=profile_root,
            repo_root=repo_root,
            deterministic=deterministic,
        )
        if artifact_uri is not None:
            return artifact_uri
    return "profile"


def _extract_artifact_uri(
    line: str, *, profile_root: Path, repo_root: Path, deterministic: bool
) -> str | None:
    file_uri_match = _FILE_URI_RE.search(line)
    if file_uri_match:
        parsed = urlparse(file_uri_match.group(0).rstrip(":"))
        if parsed.scheme == "file":
            return _normalize_artifact_path(
                unquote(parsed.path),
                profile_root=profile_root,
                repo_root=repo_root,
                deterministic=deterministic,
            )
        return file_uri_match.group(0).rstrip(":")

    prefix = line.split(":", 1)[0].strip()
    if prefix and _looks_like_path(prefix):
        return _normalize_artifact_path(
            prefix, profile_root=profile_root, repo_root=repo_root, deterministic=deterministic
        )

    path_match = _PATH_RE.search(line)
    if path_match:
        return _normalize_artifact_path(
            path_match.group(0).rstrip(":"),
            profile_root=profile_root,
            repo_root=repo_root,
            deterministic=deterministic,
        )

    return None


def _normalize_evidence_line(
    line: str, *, profile_root: Path, repo_root: Path, deterministic: bool
) -> str:
    file_uri_match = _FILE_URI_RE.search(line)
    if file_uri_match:
        raw_uri = file_uri_match.group(0).rstrip(":")
        parsed = urlparse(raw_uri)
        if parsed.scheme == "file":
            normalized = _normalize_artifact_path(
                unquote(parsed.path),
                profile_root=profile_root,
                repo_root=repo_root,
                deterministic=deterministic,
            )
            return line.replace(raw_uri, normalized, 1)
        return line

    path_match = _PATH_RE.search(line)
    if path_match:
        raw_path = path_match.group(0).rstrip(":")
        normalized = _normalize_artifact_path(
            raw_path,
            profile_root=profile_root,
            repo_root=repo_root,
            deterministic=deterministic,
        )
        return line.replace(raw_path, normalized, 1)

    return line


def _normalize_artifact_path(
    raw_path: str, *, profile_root: Path, repo_root: Path, deterministic: bool = False
) -> str:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        return raw_path.replace("\\", "/")

    resolved_candidate = candidate.resolve(strict=False)
    resolved_repo_root = repo_root.resolve(strict=False)
    resolved_profile_root = profile_root.resolve(strict=False)

    for root in (resolved_repo_root, resolved_profile_root):
        try:
            relative = resolved_candidate.relative_to(root)
        except ValueError:
            continue
        relative_text = relative.as_posix()
        return relative_text if relative_text else "profile"

    if deterministic:
        return f"EXTERNAL/{candidate.name}"
    return resolved_candidate.as_posix()


def _rule_help_uri(rule_id: str) -> str:
    return f"docs/SARIF.md#rule-{_slugify(rule_id)}"


def _rule_tags(finding: Finding) -> list[str]:
    return sorted(
        {
            finding.category.lower(),
            f"confidence/{finding.confidence}",
            f"severity/{finding.severity.lower()}",
        }
    )


def _build_partial_fingerprints(
    *, finding: Finding, artifact_uri: str, evidence_lines: list[str]
) -> dict[str, str]:
    stable_material = "|".join(
        [
            finding.id,
            finding.severity,
            artifact_uri,
            "\n".join(evidence_lines),
        ]
    )
    evidence_material = "|".join(evidence_lines)
    return {
        "foxclaw/resultFingerprint/v1": _sha256_hex(stable_material),
        "foxclaw/evidenceFingerprint/v1": _sha256_hex(evidence_material),
    }


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug if slug else "rule"


def _looks_like_path(text: str) -> bool:
    return "/" in text or text.endswith(_LIKELY_FILE_SUFFIXES)
