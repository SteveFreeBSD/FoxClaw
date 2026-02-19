"""SARIF 2.1.0 rendering helpers for FoxClaw findings."""

from __future__ import annotations

import json
import re

from foxclaw.models import EvidenceBundle, Finding

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
_SEVERITY_TO_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "INFO": "note"}
_FILE_URI_RE = re.compile(r"file://[^\s,;()]+")
_PATH_RE = re.compile(r"/[^\s,;()]+")


def render_scan_sarif(bundle: EvidenceBundle) -> str:
    """Render a deterministic SARIF payload for scan findings."""
    payload = build_scan_sarif(bundle)
    return json.dumps(payload, indent=2, sort_keys=True)


def build_scan_sarif(bundle: EvidenceBundle) -> dict[str, object]:
    """Build SARIF object for FoxClaw findings."""
    rules = _build_rules(bundle.findings)
    results = [_finding_to_result(finding) for finding in bundle.findings]

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FoxClaw",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _build_rules(findings: list[Finding]) -> list[dict[str, object]]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped.setdefault(finding.id, finding)

    rules: list[dict[str, object]] = []
    for rule_id in sorted(deduped):
        finding = deduped[rule_id]
        rules.append(
            {
                "id": finding.id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.rationale},
                "help": {"text": finding.recommendation},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL[finding.severity]
                },
                "properties": {
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "foxclawSeverity": finding.severity,
                },
            }
        )
    return rules


def _finding_to_result(finding: Finding) -> dict[str, object]:
    artifact_uri = _find_artifact_uri(finding.evidence)
    evidence_lines = finding.evidence if finding.evidence else ["No additional evidence."]
    evidence_text = " | ".join(evidence_lines)

    return {
        "ruleId": finding.id,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {
            "text": (
                f"{finding.title}. {finding.rationale} "
                f"Recommendation: {finding.recommendation}. Evidence: {evidence_text}"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                    }
                }
            }
        ],
        "properties": {
            "category": finding.category,
            "confidence": finding.confidence,
            "foxclawSeverity": finding.severity,
            "evidence": finding.evidence,
        },
    }


def _find_artifact_uri(evidence: list[str]) -> str:
    for line in evidence:
        file_uri_match = _FILE_URI_RE.search(line)
        if file_uri_match:
            return file_uri_match.group(0).rstrip(":")

        path_match = _PATH_RE.search(line)
        if path_match:
            return path_match.group(0).rstrip(":")
    return "foxclaw://profile"
