"""Rich text rendering for scan summaries."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from foxclaw.models import EvidenceBundle


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
        "SQLite checks (total/non-ok)",
        f"{bundle.summary.sqlite_checks_total}/{bundle.summary.sqlite_non_ok_count}",
    )
    table.add_row("Total HIGH findings", str(bundle.summary.high_findings_count))
    console.print(table)
