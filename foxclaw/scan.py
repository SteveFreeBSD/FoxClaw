"""Scan orchestration for read-only evidence collection."""

from __future__ import annotations

import os
from pathlib import Path

from foxclaw.collect.filesystem import collect_file_permissions
from foxclaw.collect.policies import collect_policies
from foxclaw.collect.prefs import collect_prefs
from foxclaw.collect.sqlite import collect_sqlite_quick_checks
from foxclaw.models import (
    EvidenceBundle,
    FilePermEvidence,
    Finding,
    ProfileEvidence,
    ScanSummary,
)
from foxclaw.profiles import FirefoxProfile
from foxclaw.rules.engine import DEFAULT_RULESET_PATH, evaluate_rules, load_ruleset

_PROFILE_LOCK_FILES = ("parent.lock", "lock")


def run_scan(profile: FirefoxProfile, *, ruleset_path: Path | None = None) -> EvidenceBundle:
    """Collect evidence for a selected profile and compute summary/high findings."""
    profile_dir = profile.path
    if not profile_dir.exists() or not profile_dir.is_dir():
        raise FileNotFoundError(f"Profile directory is not accessible: {profile_dir}")
    if not os.access(profile_dir, os.R_OK | os.X_OK):
        raise PermissionError(f"Profile directory is not readable: {profile_dir}")

    prefs = collect_prefs(profile_dir)
    filesystem = collect_file_permissions(profile_dir)
    policies = collect_policies()
    sqlite = collect_sqlite_quick_checks(profile_dir)

    high_risk_perms_count = _count_high_risk_permissions(filesystem)
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
        sqlite_checks_total=len(sqlite.checks),
        sqlite_non_ok_count=sqlite_non_ok_count,
    )
    provisional_bundle = EvidenceBundle(
        profile=profile_evidence,
        prefs=prefs,
        filesystem=filesystem,
        policies=policies,
        sqlite=sqlite,
        summary=provisional_summary,
    )

    resolved_ruleset_path = resolve_ruleset_path(ruleset_path)
    ruleset = load_ruleset(resolved_ruleset_path)
    findings = evaluate_rules(provisional_bundle, ruleset)
    findings_by_severity = _count_findings_by_severity(findings)
    high_finding_ids = [item.id for item in findings if item.severity == "HIGH"]
    summary = ScanSummary(
        prefs_parsed=len(prefs.root),
        sensitive_files_checked=len(filesystem),
        high_risk_perms_count=high_risk_perms_count,
        policies_found=len(policies.discovered_paths),
        sqlite_checks_total=len(sqlite.checks),
        sqlite_non_ok_count=sqlite_non_ok_count,
        findings_total=len(findings),
        findings_high_count=findings_by_severity["HIGH"],
        findings_medium_count=findings_by_severity["MEDIUM"],
        findings_info_count=findings_by_severity["INFO"],
    )

    return EvidenceBundle(
        profile=profile_evidence,
        prefs=prefs,
        filesystem=filesystem,
        policies=policies,
        sqlite=sqlite,
        summary=summary,
        high_findings=high_finding_ids,
        findings=findings,
    )


def resolve_ruleset_path(ruleset_path: Path | None) -> Path:
    """Resolve scan ruleset path to an absolute path."""
    candidate = ruleset_path or DEFAULT_RULESET_PATH
    return candidate.expanduser().resolve(strict=False)


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
