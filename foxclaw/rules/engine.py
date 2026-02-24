"""Ruleset loading and finding evaluation."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from foxclaw.models import SEVERITY_ORDER, EvidenceBundle, Finding, Ruleset
from foxclaw.rules.dsl import evaluate_check

DEFAULT_RULESET_PATH = Path(__file__).resolve().parents[1] / "rulesets" / "balanced.yml"
_LOG = logging.getLogger(__name__)


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

    # Bundle provenance extraction
    manifest_path = path.parent / "__manifest__.json"
    if manifest_path.exists():
        from foxclaw.models import BundleProvenance
        from foxclaw.rules.trust import RulesetBundleManifest

        try:
            raw_manifest = json.loads(manifest_path.read_bytes().decode("utf-8"))
            bundle_manifest = RulesetBundleManifest.model_validate(raw_manifest)
            ruleset.bundle_provenance = BundleProvenance(
                bundle_name=bundle_manifest.bundle_name,
                bundle_version=bundle_manifest.bundle_version,
                manifest_signature=bundle_manifest.manifest_signature.signature,
                verified_at=bundle_manifest.created_at,  # This uses the bundle's creation time, could be verified time if we stored it
            )
        except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
            # Runtime scan stays fail-open for provenance metadata parsing;
            # authenticity checks happen during bundle install/verify commands.
            _LOG.debug("ignoring bundle provenance metadata at %s: %s", manifest_path, exc)

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
    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.id))


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
