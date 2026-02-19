"""Scan orchestration for read-only evidence collection."""

from __future__ import annotations

import os

from foxclaw.collect.filesystem import collect_file_permissions
from foxclaw.collect.policies import collect_policies
from foxclaw.collect.prefs import collect_prefs
from foxclaw.collect.sqlite import collect_sqlite_quick_checks
from foxclaw.models import (
    EvidenceBundle,
    FilePermEvidence,
    ProfileEvidence,
    ScanSummary,
    SqliteCheck,
)
from foxclaw.profiles import FirefoxProfile


def run_scan(profile: FirefoxProfile) -> EvidenceBundle:
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

    high_findings = _build_high_findings(filesystem=filesystem, sqlite_checks=sqlite.checks)
    high_risk_perms_count = _count_high_risk_permissions(filesystem)
    sqlite_non_ok_count = sum(
        1 for check in sqlite.checks if check.quick_check_result.strip().lower() != "ok"
    )

    summary = ScanSummary(
        prefs_parsed=len(prefs.root),
        sensitive_files_checked=len(filesystem),
        high_risk_perms_count=high_risk_perms_count,
        policies_found=len(policies.discovered_paths),
        sqlite_checks_total=len(sqlite.checks),
        sqlite_non_ok_count=sqlite_non_ok_count,
        high_findings_count=len(high_findings),
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

    return EvidenceBundle(
        profile=profile_evidence,
        prefs=prefs,
        filesystem=filesystem,
        policies=policies,
        sqlite=sqlite,
        summary=summary,
        high_findings=high_findings,
    )


def _count_high_risk_permissions(filesystem: list[FilePermEvidence]) -> int:
    return sum(
        1
        for file_evidence in filesystem
        if file_evidence.group_readable or file_evidence.world_readable
    )


def _build_high_findings(
    *, filesystem: list[FilePermEvidence], sqlite_checks: list[SqliteCheck]
) -> list[str]:
    findings: list[str] = []
    for file_evidence in filesystem:
        if file_evidence.group_readable or file_evidence.world_readable:
            findings.append(
                f"Sensitive file is group/world readable: {file_evidence.path} ({file_evidence.mode})"
            )

    for check in sqlite_checks:
        if check.quick_check_result.strip().lower() != "ok":
            findings.append(
                f"SQLite quick_check not ok for {check.db_path}: {check.quick_check_result}"
            )
    return findings
