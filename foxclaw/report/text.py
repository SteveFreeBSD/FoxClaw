"""Rich text rendering for scan summaries."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.table import Table

from foxclaw.models import EvidenceBundle, ExtensionEntry


def render_scan_summary(console: Console, bundle: EvidenceBundle) -> None:
    """Render a compact scan summary."""
    console.print(f"Selected profile: {bundle.profile.path}")

    table = Table(title="Scan Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Preferences parsed", str(bundle.summary.prefs_parsed))
    table.add_row("Sensitive files checked", str(bundle.summary.sensitive_files_checked))
    table.add_row("High-risk permissions", str(bundle.summary.high_risk_perms_count))
    table.add_row("Policies found", str(bundle.summary.policies_found))
    table.add_row(
        "Extensions (found/active)",
        f"{bundle.summary.extensions_found}/{bundle.summary.extensions_active}",
    )
    table.add_row(
        "Extension risk (unsigned/high-risk/debug)",
        (
            f"{bundle.summary.extensions_unsigned_count}/"
            f"{bundle.summary.extensions_high_risk_count}/"
            f"{bundle.summary.extensions_debug_count}"
        ),
    )
    table.add_row(
        "SQLite checks (total/non-ok)",
        f"{bundle.summary.sqlite_checks_total}/{bundle.summary.sqlite_non_ok_count}",
    )
    table.add_row("Findings suppressed", str(bundle.summary.findings_suppressed_count))
    table.add_row("Total HIGH findings", str(bundle.summary.findings_high_count))
    console.print(table)
    _render_extension_posture(console, bundle)
    _render_suppression_summary(console, bundle)

    counts = Counter(finding.severity for finding in bundle.findings)
    high_rule_ids = [
        finding.id for finding in bundle.findings if finding.severity == "HIGH"
    ][:5]

    findings_table = Table(title="Rule Findings Summary")
    findings_table.add_column("Metric")
    findings_table.add_column("Value", justify="right")
    findings_table.add_row("Findings HIGH", str(counts.get("HIGH", 0)))
    findings_table.add_row("Findings MEDIUM", str(counts.get("MEDIUM", 0)))
    findings_table.add_row("Findings INFO", str(counts.get("INFO", 0)))
    findings_table.add_row("Findings total", str(len(bundle.findings)))
    findings_table.add_row(
        "Top 5 HIGH rule IDs",
        ", ".join(high_rule_ids) if high_rule_ids else "-",
    )
    console.print(findings_table)


def _render_extension_posture(console: Console, bundle: EvidenceBundle) -> None:
    if not bundle.extensions.entries:
        return

    table = Table(title="Extension Posture")
    table.add_column("Addon ID")
    table.add_column("Source")
    table.add_column("Active", justify="center")
    table.add_column("Signed")
    table.add_column("Manifest")
    table.add_column("Risk (H/M)", justify="right")
    table.add_column("Notes")

    for entry in bundle.extensions.entries:
        high_risk = sum(1 for risk in entry.risky_permissions if risk.level == "high")
        medium_risk = sum(1 for risk in entry.risky_permissions if risk.level == "medium")
        notes: list[str] = []
        if entry.debug_install:
            notes.append("debug-install")
        if entry.blocklisted:
            notes.append("blocklisted")
        if entry.parse_error:
            notes.append("parse-error")

        table.add_row(
            entry.addon_id,
            entry.source_kind,
            _format_active(entry),
            _format_signed(entry),
            _format_manifest(entry),
            f"{high_risk}/{medium_risk}",
            ", ".join(notes) if notes else "-",
        )

    console.print(table)


def _format_active(entry: ExtensionEntry) -> str:
    if entry.active is True:
        return "yes"
    if entry.active is False:
        return "no"
    return "?"


def _format_signed(entry: ExtensionEntry) -> str:
    if entry.signed_status == "valid":
        return "ok"
    if entry.signed_status == "invalid":
        return "invalid"
    if _is_system_source(entry):
        return "n/a"
    return "unknown"


def _format_manifest(entry: ExtensionEntry) -> str:
    if entry.manifest_status == "parsed":
        if entry.manifest_version is None:
            return "parsed"
        return f"mv{entry.manifest_version}"
    if entry.manifest_status == "error":
        return "error"
    if _is_system_source(entry):
        return "n/a"
    return "missing"


def _is_system_source(entry: ExtensionEntry) -> bool:
    return entry.source_kind in {"system", "builtin"}


def _render_suppression_summary(console: Console, bundle: EvidenceBundle) -> None:
    if not bundle.suppressions.source_paths:
        return

    table = Table(title="Suppression Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Suppression files", str(len(bundle.suppressions.source_paths)))
    table.add_row("Applied suppressions", str(len(bundle.suppressions.applied)))
    table.add_row("Expired suppressions", str(len(bundle.suppressions.expired)))
    console.print(table)
