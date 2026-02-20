from __future__ import annotations

from foxclaw.models import (
    EvidenceBundle,
    ExtensionEntry,
    ExtensionEvidence,
    PolicyEvidence,
    PrefEvidence,
    ProfileEvidence,
    ScanSummary,
    SqliteEvidence,
)
from foxclaw.report.text import render_scan_summary
from rich.console import Console


def _bundle_with_extensions(entries: list[ExtensionEntry]) -> EvidenceBundle:
    return EvidenceBundle(
        profile=ProfileEvidence(
            profile_id="Profile0",
            name="default",
            path="/tmp/profile",
            selected=True,
            lock_detected=False,
            lock_files=[],
        ),
        prefs=PrefEvidence(root={}),
        filesystem=[],
        policies=PolicyEvidence(),
        extensions=ExtensionEvidence(
            addons_seen=len(entries),
            active_addons=sum(1 for entry in entries if entry.active is True),
            entries=entries,
        ),
        sqlite=SqliteEvidence(checks=[]),
        summary=ScanSummary(
            prefs_parsed=0,
            sensitive_files_checked=0,
            high_risk_perms_count=0,
            policies_found=0,
            extensions_found=len(entries),
            extensions_active=sum(1 for entry in entries if entry.active is True),
            extensions_high_risk_count=0,
            extensions_unsigned_count=0,
            extensions_debug_count=0,
            sqlite_checks_total=0,
            sqlite_non_ok_count=0,
            findings_total=0,
            findings_high_count=0,
            findings_medium_count=0,
            findings_info_count=0,
        ),
        findings=[],
        high_findings=[],
    )


def test_render_scan_summary_shows_na_for_system_extension_signature_and_manifest() -> None:
    bundle = _bundle_with_extensions(
        [
            ExtensionEntry(
                addon_id="screenshots@mozilla.org",
                active=True,
                source_kind="system",
                signed_status="unavailable",
                manifest_status="unavailable",
            )
        ]
    )
    console = Console(record=True, width=160)
    render_scan_summary(console, bundle)
    output = console.export_text()

    assert "Extension Posture" in output
    assert "screenshots@mozilla.org" in output
    assert output.count("n/a") >= 2
    assert "Extension risk (unsigned/high-risk/debug)" in output
