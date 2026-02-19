"""Ruleset loading and finding evaluation."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from foxclaw.models import EvidenceBundle, Finding, Ruleset
from foxclaw.rules.dsl import evaluate_check

DEFAULT_RULESET_PATH = Path(__file__).resolve().parents[1] / "rulesets" / "balanced.yml"
_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def load_ruleset(path: Path) -> Ruleset:
    """Load and validate a YAML ruleset from disk."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"Unable to read ruleset file: {path}: {exc}") from exc

    try:
        payload = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"Unable to parse ruleset YAML: {path}: {exc}") from exc

    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError(f"Ruleset must be a YAML object: {path}")

    try:
        ruleset = Ruleset.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"Ruleset validation failed: {path}: {exc}") from exc

    _validate_unique_rule_ids(ruleset)
    return ruleset


def load_default_ruleset() -> Ruleset:
    """Load the built-in balanced ruleset."""
    return load_ruleset(DEFAULT_RULESET_PATH)


def evaluate_rules(bundle: EvidenceBundle, ruleset: Ruleset) -> list[Finding]:
    """Evaluate all rules and return deterministic finding output."""
    findings: list[Finding] = []
    for rule in ruleset.rules:
        result = evaluate_check(bundle, rule.check)
        if result.passed:
            continue

        findings.append(
            Finding(
                id=rule.id,
                title=rule.title,
                severity=rule.severity,
                category=rule.category,
                rationale=rule.rationale,
                recommendation=rule.recommendation,
                confidence=rule.confidence,
                evidence=result.evidence,
            )
        )

    return sort_findings(findings)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity then rule id for deterministic output."""
    return sorted(findings, key=lambda item: (_SEVERITY_ORDER[item.severity], item.id))


def _validate_unique_rule_ids(ruleset: Ruleset) -> None:
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule in ruleset.rules:
        if rule.id in seen:
            duplicates.append(rule.id)
        seen.add(rule.id)

    if duplicates:
        duplicate_ids = ", ".join(sorted(set(duplicates)))
        raise ValueError(f"Ruleset contains duplicate rule IDs: {duplicate_ids}")
