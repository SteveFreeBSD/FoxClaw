"""Scan orchestration for read-only evidence collection."""

from __future__ import annotations

import os
from pathlib import Path

from foxclaw.collect.artifacts import collect_profile_artifacts
from foxclaw.collect.extensions import collect_extensions
from foxclaw.collect.filesystem import collect_file_permissions
from foxclaw.collect.policies import collect_policies
from foxclaw.collect.prefs import collect_prefs
from foxclaw.collect.sqlite import collect_sqlite_quick_checks
from foxclaw.intel.blocklist import apply_extension_blocklist_from_snapshot
from foxclaw.intel.correlation import correlate_firefox_vulnerability_intel
from foxclaw.intel.reputation import apply_extension_reputation_from_snapshot
from foxclaw.models import (
    EvidenceBundle,
    FilePermEvidence,
    Finding,
    ProfileEvidence,
    ScanSummary,
)
from foxclaw.profiles import FirefoxProfile
from foxclaw.rules.engine import (
    DEFAULT_RULESET_PATH,
    evaluate_rules,
    load_ruleset,
    sort_findings,
)
from foxclaw.rules.suppressions import apply_suppressions

_PROFILE_LOCK_FILES = ("parent.lock", "lock")


def run_scan(
    profile: FirefoxProfile,
    *,
    ruleset_path: Path | None = None,
    policy_paths: list[Path] | None = None,
    suppression_paths: list[Path] | None = None,
    intel_store_dir: Path | None = None,
    intel_snapshot_id: str | None = None,
) -> EvidenceBundle:
    """Collect evidence for a selected profile and compute summary/high findings."""
    profile_dir = profile.path
    if not profile_dir.exists() or not profile_dir.is_dir():
        raise FileNotFoundError(f"Profile directory is not accessible: {profile_dir}")
    if not os.access(profile_dir, os.R_OK | os.X_OK):
        raise PermissionError(f"Profile directory is not readable: {profile_dir}")

    prefs = collect_prefs(profile_dir)
    filesystem = collect_file_permissions(profile_dir)
    normalized_policy_paths = _normalize_policy_paths(policy_paths)
    normalized_suppression_paths = _normalize_suppression_paths(suppression_paths)
    policies = collect_policies(policy_paths=normalized_policy_paths)
    intel, intel_findings = correlate_firefox_vulnerability_intel(
        profile_dir=profile_dir,
        intel_store_dir=intel_store_dir,
        intel_snapshot_id=intel_snapshot_id,
    )
    extensions = collect_extensions(profile_dir)
    artifacts = collect_profile_artifacts(profile_dir)
    if intel.enabled and intel.store_dir is not None and intel.snapshot_id is not None:
        apply_extension_blocklist_from_snapshot(
            extensions=extensions,
            store_dir=Path(intel.store_dir),
            snapshot_id=intel.snapshot_id,
        )
        apply_extension_reputation_from_snapshot(
            extensions=extensions,
            store_dir=Path(intel.store_dir),
            snapshot_id=intel.snapshot_id,
        )
    sqlite = collect_sqlite_quick_checks(profile_dir)

    high_risk_perms_count = _count_high_risk_permissions(filesystem)
    extensions_high_risk_count = sum(
        1
        for extension in extensions.entries
        if extension.active
        and extension.source_kind not in {"system", "builtin"}
        and any(risk.level == "high" for risk in extension.risky_permissions)
    )
    extensions_unsigned_count = sum(
        1
        for extension in extensions.entries
        if extension.active
        and extension.source_kind not in {"system", "builtin"}
        and extension.signed_valid is False
    )
    extensions_debug_count = sum(
        1
        for extension in extensions.entries
        if extension.active
        and extension.source_kind not in {"system", "builtin"}
        and extension.debug_install
    )
    sqlite_non_ok_count = sum(
        1 for check in sqlite.checks if check.quick_check_result.strip().lower() != "ok"
    )
    profile_evidence = ProfileEvidence(
        profile_id=profile.profile_id,
        name=profile.name,
        path=str(profile.path),
        selected=profile.selected,
        selection_reason=profile.selection_reason,
        lock_detected=profile.lock_detected,
        lock_files=profile.lock_files,
    )

    provisional_summary = ScanSummary(
        prefs_parsed=len(prefs.root),
        sensitive_files_checked=len(filesystem),
        high_risk_perms_count=high_risk_perms_count,
        policies_found=len(policies.discovered_paths),
        extensions_found=extensions.addons_seen,
        extensions_active=extensions.active_addons,
        extensions_high_risk_count=extensions_high_risk_count,
        extensions_unsigned_count=extensions_unsigned_count,
        extensions_debug_count=extensions_debug_count,
        sqlite_checks_total=len(sqlite.checks),
        sqlite_non_ok_count=sqlite_non_ok_count,
        intel_matches_count=len(intel.matched_advisories),
    )
    provisional_bundle = EvidenceBundle(
        profile=profile_evidence,
        prefs=prefs,
        filesystem=filesystem,
        policies=policies,
        extensions=extensions,
        sqlite=sqlite,
        artifacts=artifacts,
        intel=intel,
        summary=provisional_summary,
    )

    resolved_ruleset_path = resolve_ruleset_path(ruleset_path)
    ruleset = load_ruleset(resolved_ruleset_path)
    findings = evaluate_rules(provisional_bundle, ruleset)
    findings = sort_findings([*findings, *intel_findings])
    findings, suppression_evidence = apply_suppressions(
        findings,
        profile_path=profile_dir,
        suppression_paths=normalized_suppression_paths,
    )
    findings_by_severity = _count_findings_by_severity(findings)
    high_finding_ids = [item.id for item in findings if item.severity == "HIGH"]
    summary = ScanSummary(
        prefs_parsed=len(prefs.root),
        sensitive_files_checked=len(filesystem),
        high_risk_perms_count=high_risk_perms_count,
        policies_found=len(policies.discovered_paths),
        extensions_found=extensions.addons_seen,
        extensions_active=extensions.active_addons,
        extensions_high_risk_count=extensions_high_risk_count,
        extensions_unsigned_count=extensions_unsigned_count,
        extensions_debug_count=extensions_debug_count,
        sqlite_checks_total=len(sqlite.checks),
        sqlite_non_ok_count=sqlite_non_ok_count,
        intel_matches_count=len(intel.matched_advisories),
        findings_total=len(findings),
        findings_high_count=findings_by_severity["HIGH"],
        findings_medium_count=findings_by_severity["MEDIUM"],
        findings_info_count=findings_by_severity["INFO"],
        findings_suppressed_count=len(suppression_evidence.applied),
    )

    return EvidenceBundle(
        profile=profile_evidence,
        prefs=prefs,
        filesystem=filesystem,
        policies=policies,
        extensions=extensions,
        sqlite=sqlite,
        artifacts=artifacts,
        intel=intel,
        summary=summary,
        high_findings=high_finding_ids,
        findings=findings,
        suppressions=suppression_evidence,
    )


def resolve_ruleset_path(ruleset_path: Path | None) -> Path:
    """Resolve scan ruleset path to an absolute path."""
    candidate = ruleset_path or DEFAULT_RULESET_PATH
    return candidate.expanduser().resolve(strict=False)


def _normalize_policy_paths(policy_paths: list[Path] | None) -> list[Path] | None:
    if policy_paths is None:
        return None

    normalized: list[Path] = []
    seen: set[Path] = set()
    for path in policy_paths:
        normalized_path = Path(os.path.abspath(str(path.expanduser())))
        if normalized_path in seen:
            continue
        normalized.append(normalized_path)
        seen.add(normalized_path)
    return normalized


def _normalize_suppression_paths(suppression_paths: list[Path] | None) -> list[Path] | None:
    if suppression_paths is None:
        return None

    normalized: list[Path] = []
    seen: set[Path] = set()
    for path in suppression_paths:
        resolved = path.expanduser().resolve(strict=False)
        if resolved in seen:
            continue
        normalized.append(resolved)
        seen.add(resolved)
    return normalized


def _count_high_risk_permissions(filesystem: list[FilePermEvidence]) -> int:
    return sum(
        1
        for file_evidence in filesystem
        if file_evidence.group_readable or file_evidence.world_readable
    )


def _count_findings_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def detect_active_profile_reason(profile_dir: Path) -> str | None:
    """Return activity reason for a profile, or None when profile appears quiet."""
    lock_files = [
        lock_name for lock_name in _PROFILE_LOCK_FILES if (profile_dir / lock_name).exists()
    ]
    if lock_files:
        return f"lock file(s) present: {', '.join(lock_files)}"

    if _has_running_firefox_process():
        return "running firefox process detected"
    return None


def _has_running_firefox_process() -> bool:
    proc_dir = Path("/proc")
    if not proc_dir.is_dir():
        return False

    for pid_dir in proc_dir.iterdir():
        if not pid_dir.name.isdigit():
            continue

        comm_path = pid_dir / "comm"
        try:
            comm = comm_path.read_text(encoding="utf-8", errors="ignore").strip().lower()
        except OSError:
            comm = ""
        if "firefox" in comm:
            return True

        cmdline_path = pid_dir / "cmdline"
        try:
            raw_cmdline = cmdline_path.read_bytes()
        except OSError:
            continue
        cmdline = raw_cmdline.replace(b"\x00", b" ").decode("utf-8", errors="ignore").lower()
        if "firefox" in cmdline:
            return True
    return False
