"""CLI entrypoint for foxclaw."""

import hashlib
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from foxclaw.intel.sync import sync_sources
from foxclaw.profiles import FirefoxProfile, discover_profiles
from foxclaw.report.fleet import build_fleet_report, render_fleet_json
from foxclaw.report.jsonout import render_scan_json
from foxclaw.report.sarif import render_scan_sarif
from foxclaw.report.snapshot import render_scan_snapshot
from foxclaw.report.snapshot_diff import (
    build_scan_snapshot_diff,
    load_scan_snapshot,
    render_snapshot_diff_json,
    render_snapshot_diff_summary,
)
from foxclaw.report.text import render_scan_summary
from foxclaw.rules.engine import load_ruleset
from foxclaw.rules.trust import verify_ruleset_with_manifest
from foxclaw.scan import detect_active_profile_reason, resolve_ruleset_path, run_scan

EXIT_OK = 0
EXIT_OPERATIONAL_ERROR = 1
EXIT_HIGH_FINDINGS = 2

app = typer.Typer(help="FoxClaw: deterministic Firefox security posture scanner.")
profiles_app = typer.Typer(help="Firefox profile discovery commands.")
snapshot_app = typer.Typer(help="Snapshot baseline and drift commands.")
intel_app = typer.Typer(help="Threat intelligence synchronization commands.")
fleet_app = typer.Typer(help="Fleet and multi-profile aggregation commands.")
suppression_app = typer.Typer(help="Suppression governance commands.")
bundle_app = typer.Typer(help="External ruleset bundle distribution commands.")
console = Console()


@profiles_app.command("list")
def profiles_list() -> None:
    """List discovered profiles."""
    report = discover_profiles()
    if report.profiles_ini is None or not report.profiles:
        console.print("[yellow]No Firefox profiles discovered.[/yellow]")
        if report.searched_dirs:
            console.print("Searched directories:")
            for search_dir in report.searched_dirs:
                console.print(f"  - {search_dir}")
        raise typer.Exit(code=EXIT_OK)

    console.print(f"profiles.ini: {report.profiles_ini}")
    table = Table(title="Discovered Firefox Profiles")
    table.add_column("Profile ID")
    table.add_column("Name")
    table.add_column("Path")
    table.add_column("Default")
    table.add_column("Lock")
    table.add_column("Lock Files")
    table.add_column("places.sqlite (bytes)", justify="right")
    table.add_column("Dir mtime")
    table.add_column("Score", justify="right")
    table.add_column("Selected")

    for profile in sorted(report.profiles, key=lambda item: item.profile_id):
        mtime = (
            datetime.fromtimestamp(profile.directory_mtime).isoformat(timespec="seconds")
            if profile.directory_mtime > 0
            else "-"
        )
        table.add_row(
            profile.profile_id,
            profile.name,
            str(profile.path),
            "yes" if profile.default_flag else "no",
            "yes" if profile.lock_detected else "no",
            ",".join(profile.lock_files) if profile.lock_files else "-",
            str(profile.places_size_bytes),
            mtime,
            f"{profile.total_score:.2f}",
            "yes" if profile.selected else "no",
        )

    console.print(table)
    if report.selected_profile_id:
        console.print(f"Selected profile: {report.selected_profile_id}")
    if report.selection_reason:
        console.print(f"Selection reason: {report.selection_reason}")
    raise typer.Exit(code=EXIT_OK)


@app.command("scan")
def scan(
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON report to stdout."
    ),
    profile: Path | None = typer.Option(
        None, "--profile", help="Scan this Firefox profile directory directly."
    ),
    require_quiet_profile: bool = typer.Option(
        False,
        "--require-quiet-profile",
        help="Fail if the selected profile appears active (lock file or firefox process).",
    ),
    ruleset: Path | None = typer.Option(
        None, "--ruleset", help="Path to YAML ruleset (default: balanced ruleset)."
    ),
    ruleset_trust_manifest: Path | None = typer.Option(
        None,
        "--ruleset-trust-manifest",
        help=(
            "Verify ruleset digest/signatures against this trust manifest "
            "(fail closed on mismatch)."
        ),
    ),
    require_ruleset_signatures: bool = typer.Option(
        False,
        "--require-ruleset-signatures",
        help="Require at least one valid signature in ruleset trust manifest entry.",
    ),
    policy_path: list[Path] | None = typer.Option(
        None,
        "--policy-path",
        help=(
            "Override enterprise policy discovery path(s); "
            "repeatable and defaults are ignored when provided."
        ),
    ),
    suppression_path: list[Path] | None = typer.Option(
        None,
        "--suppression-path",
        help=(
            "Apply suppression policy file(s); "
            "repeatable and evaluated deterministically by path + rule."
        ),
    ),
    intel_store_dir: Path | None = typer.Option(
        None,
        "--intel-store-dir",
        help=(
            "Enable offline vulnerability correlation from this local intel store "
            "(defaults to XDG/HOME intel path when --intel-snapshot-id is set)."
        ),
    ),
    intel_snapshot_id: str | None = typer.Option(
        None,
        "--intel-snapshot-id",
        help=(
            "Correlate against this synced intel snapshot id; "
            "use 'latest' or omit to resolve from store latest pointer."
        ),
    ),
    sarif_output: bool = typer.Option(
        False, "--sarif", help="Emit SARIF 2.1.0 report to stdout."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write JSON report to this path."
    ),
    sarif_out: Path | None = typer.Option(
        None, "--sarif-out", help="Write SARIF 2.1.0 report to this path."
    ),
    snapshot_out: Path | None = typer.Option(
        None,
        "--snapshot-out",
        help="Write deterministic snapshot JSON to this path.",
    ),
) -> None:
    """Run read-only scan."""
    if json_output and sarif_output:
        console.print("[red]Operational error: --json and --sarif are mutually exclusive.[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    selected_profile: FirefoxProfile | None = None
    if profile is not None:
        selected_profile = _build_profile_override(profile)
    else:
        report = discover_profiles()
        selected_profile = next((p for p in report.profiles if p.selected), None)
        if selected_profile is None:
            console.print("[red]Operational error: no Firefox profile selected.[/red]")
            if report.searched_dirs:
                console.print("Searched directories:")
                for search_dir in report.searched_dirs:
                    console.print(f"  - {search_dir}")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    if require_quiet_profile:
        active_reason = detect_active_profile_reason(selected_profile.path)
        if active_reason is not None:
            console.print(
                "[red]Operational error: quiet profile required; "
                f"profile appears active ({active_reason}).[/red]"
            )
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    resolved_ruleset_path = resolve_ruleset_path(ruleset)

    try:
        if ruleset_trust_manifest is not None:
            verify_ruleset_with_manifest(
                ruleset_path=resolved_ruleset_path,
                manifest_path=ruleset_trust_manifest.expanduser().resolve(strict=False),
                require_signatures=require_ruleset_signatures,
            )
        evidence = run_scan(
            selected_profile,
            ruleset_path=resolved_ruleset_path,
            policy_paths=policy_path,
            suppression_paths=suppression_path,
            intel_store_dir=intel_store_dir,
            intel_snapshot_id=intel_snapshot_id,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Operational error: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    json_payload: str | None = None
    sarif_payload: str | None = None
    snapshot_payload: str | None = None
    if json_output or output is not None:
        json_payload = render_scan_json(evidence)
    if sarif_output or sarif_out is not None:
        sarif_payload = render_scan_sarif(evidence)

    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            if json_payload is None:
                json_payload = render_scan_json(evidence)
            output.write_text(json_payload, encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Operational error writing output: {exc}[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc
    if sarif_out is not None:
        try:
            sarif_out.parent.mkdir(parents=True, exist_ok=True)
            if sarif_payload is None:
                sarif_payload = render_scan_sarif(evidence)
            sarif_out.write_text(sarif_payload, encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Operational error writing SARIF output: {exc}[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc
    if snapshot_out is not None:
        try:
            snapshot_out.parent.mkdir(parents=True, exist_ok=True)
            if snapshot_payload is None:
                snapshot_ruleset = load_ruleset(resolved_ruleset_path)
                snapshot_payload = render_scan_snapshot(
                    evidence,
                    ruleset_path=resolved_ruleset_path,
                    ruleset_name=snapshot_ruleset.name,
                    ruleset_version=snapshot_ruleset.version,
                )
            snapshot_out.write_text(snapshot_payload, encoding="utf-8")
        except (OSError, ValueError) as exc:
            console.print(f"[red]Operational error writing snapshot output: {exc}[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    if json_output and output is None:
        if json_payload is None:
            json_payload = render_scan_json(evidence)
        typer.echo(json_payload)
    elif sarif_output and sarif_out is None:
        if sarif_payload is None:
            sarif_payload = render_scan_sarif(evidence)
        typer.echo(sarif_payload)
    elif not json_output and not sarif_output:
        render_scan_summary(console, evidence)
        if output is not None:
            console.print(f"JSON report written to: {output}")
        if sarif_out is not None:
            console.print(f"SARIF report written to: {sarif_out}")
        if snapshot_out is not None:
            console.print(f"Snapshot report written to: {snapshot_out}")

    raise typer.Exit(
        code=EXIT_HIGH_FINDINGS if evidence.summary.findings_high_count > 0 else EXIT_OK
    )


@app.command("live")
def live(
    # Sync arguments
    source: list[str] = typer.Option(
        ["foxclaw-amo=tests/fixtures/intel/amo_extension_intel.v1.json"],
        "--source",
        help="Source mapping in name=origin format; repeatable (defaults to a built-in testbed origin).",
    ),
    intel_store_dir: Path | None = typer.Option(
        None,
        "--intel-store-dir",
        help="Override intelligence store directory for both sync and scan.",
    ),
    allow_insecure_http: bool = typer.Option(
        False,
        "--allow-insecure-http",
        help="Allow plaintext HTTP source URLs for explicit trusted lab mirrors.",
    ),
    # Scan arguments
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON report to stdout."
    ),
    profile: Path | None = typer.Option(
        None, "--profile", help="Scan this Firefox profile directory directly."
    ),
    require_quiet_profile: bool = typer.Option(
        False,
        "--require-quiet-profile",
        help="Fail if the selected profile appears active (lock file or firefox process).",
    ),
    ruleset: Path | None = typer.Option(
        None, "--ruleset", help="Path to YAML ruleset (default: balanced ruleset)."
    ),
    ruleset_trust_manifest: Path | None = typer.Option(
        None,
        "--ruleset-trust-manifest",
        help="Verify ruleset digest/signatures against this trust manifest (fail closed on mismatch).",
    ),
    require_ruleset_signatures: bool = typer.Option(
        False,
        "--require-ruleset-signatures",
        help="Require at least one valid signature in ruleset trust manifest entry.",
    ),
    policy_path: list[Path] | None = typer.Option(
        None,
        "--policy-path",
        help="Override enterprise policy discovery path(s); repeatable.",
    ),
    suppression_path: list[Path] | None = typer.Option(
        None,
        "--suppression-path",
        help="Apply suppression policy file(s); repeatable.",
    ),
    sarif_output: bool = typer.Option(
        False, "--sarif", help="Emit SARIF 2.1.0 report to stdout."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write JSON report to this path."
    ),
    sarif_out: Path | None = typer.Option(
        None, "--sarif-out", help="Write SARIF 2.1.0 report to this path."
    ),
    snapshot_out: Path | None = typer.Option(
        None,
        "--snapshot-out",
        help="Write deterministic snapshot JSON to this path.",
    ),
) -> None:
    """Run an intelligence sync followed by a scan in one step."""
    if json_output and sarif_output:
        console.print("[red]Operational error: --json and --sarif are mutually exclusive.[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    console.print("[blue]Step 1/2: Synchronizing intelligence sources...[/blue]")
    try:
        sync_result = sync_sources(
            source_specs=source,
            store_dir=intel_store_dir,
            normalize_json=True,
            cwd=Path.cwd(),
            allow_insecure_http=allow_insecure_http,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Sync failed: {exc}[/red]")
        console.print("[red]Aborting scan due to sync failure (fail closed).[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    snapshot_id = sync_result.manifest.snapshot_id
    console.print(f"[green]Sync successful. Snapshot pinned: {snapshot_id}[/green]")
    console.print("[blue]Step 2/2: Executing deterministic scan...[/blue]")

    # Pass the locked snapshot_id into the scan entrypoint manually to prevent duplication
    # We call the scan function's internal logic directly but inject the ID.
    
    # We must replicate the active profile checks from scan() to keep the CLI clean
    selected_profile: FirefoxProfile | None = None
    if profile is not None:
        selected_profile = _build_profile_override(profile)
    else:
        report = discover_profiles()
        selected_profile = next((p for p in report.profiles if p.selected), None)
        if selected_profile is None:
            console.print("[red]Operational error: no Firefox profile selected.[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    if require_quiet_profile:
        active_reason = detect_active_profile_reason(selected_profile.path)
        if active_reason is not None:
            console.print(f"[red]Operational error: quiet profile required; profile appears active ({active_reason}).[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    resolved_ruleset_path = resolve_ruleset_path(ruleset)

    try:
        if ruleset_trust_manifest is not None:
            verify_ruleset_with_manifest(
                ruleset_path=resolved_ruleset_path,
                manifest_path=ruleset_trust_manifest.expanduser().resolve(strict=False),
                require_signatures=require_ruleset_signatures,
            )
        evidence = run_scan(
            selected_profile,
            ruleset_path=resolved_ruleset_path,
            policy_paths=policy_path,
            suppression_paths=suppression_path,
            intel_store_dir=intel_store_dir,
            intel_snapshot_id=snapshot_id,  # The crucial deterministic pin!
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Operational error during scan: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    # Reuse output rendering
    json_payload = render_scan_json(evidence) if (json_output or output is not None) else None
    sarif_payload = render_scan_sarif(evidence) if (sarif_output or sarif_out is not None) else None

    if output is not None and json_payload is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_payload, encoding="utf-8")
    if sarif_out is not None and sarif_payload is not None:
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(sarif_payload, encoding="utf-8")
    if snapshot_out is not None:
        snapshot_ruleset = load_ruleset(resolved_ruleset_path)
        snapshot_payload = render_scan_snapshot(
            evidence,
            ruleset_path=resolved_ruleset_path,
            ruleset_name=snapshot_ruleset.name,
            ruleset_version=snapshot_ruleset.version,
        )
        snapshot_out.parent.mkdir(parents=True, exist_ok=True)
        snapshot_out.write_text(snapshot_payload, encoding="utf-8")

    if json_output and output is None and json_payload is not None:
        typer.echo(json_payload)
    elif sarif_output and sarif_out is None and sarif_payload is not None:
        typer.echo(sarif_payload)
    elif not json_output and not sarif_output:
        render_scan_summary(console, evidence)
        if output is not None:
            console.print(f"JSON report written to: {output}")
        if sarif_out is not None:
            console.print(f"SARIF report written to: {sarif_out}")
        if snapshot_out is not None:
            console.print(f"Snapshot report written to: {snapshot_out}")

    raise typer.Exit(
        code=EXIT_HIGH_FINDINGS if evidence.summary.findings_high_count > 0 else EXIT_OK
    )



@fleet_app.command("aggregate")
def fleet_aggregate(
    profile: list[Path] | None = typer.Option(
        None,
        "--profile",
        help=(
            "Scan and include this Firefox profile directory in fleet output; "
            "repeatable and defaults to all discovered profiles."
        ),
    ),
    ruleset: Path | None = typer.Option(
        None, "--ruleset", help="Path to YAML ruleset (default: balanced ruleset)."
    ),
    ruleset_trust_manifest: Path | None = typer.Option(
        None,
        "--ruleset-trust-manifest",
        help=(
            "Verify ruleset digest/signatures against this trust manifest "
            "(fail closed on mismatch)."
        ),
    ),
    require_ruleset_signatures: bool = typer.Option(
        False,
        "--require-ruleset-signatures",
        help="Require at least one valid signature in ruleset trust manifest entry.",
    ),
    policy_path: list[Path] | None = typer.Option(
        None,
        "--policy-path",
        help=(
            "Override enterprise policy discovery path(s); "
            "repeatable and defaults are ignored when provided."
        ),
    ),
    suppression_path: list[Path] | None = typer.Option(
        None,
        "--suppression-path",
        help=(
            "Apply suppression policy file(s); "
            "repeatable and evaluated deterministically by path + rule."
        ),
    ),
    intel_store_dir: Path | None = typer.Option(
        None,
        "--intel-store-dir",
        help=(
            "Enable offline vulnerability correlation from this local intel store "
            "(defaults to XDG/HOME intel path when --intel-snapshot-id is set)."
        ),
    ),
    intel_snapshot_id: str | None = typer.Option(
        None,
        "--intel-snapshot-id",
        help=(
            "Correlate against this synced intel snapshot id; "
            "use 'latest' or omit to resolve from store latest pointer."
        ),
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit merged fleet JSON report to stdout."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write merged fleet JSON report to this path."
    ),
) -> None:
    """Run multi-profile scans and emit a normalized fleet aggregation report."""
    if json_output and output is not None:
        console.print("[red]Operational error: --json and --output cannot be combined.[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    try:
        selected_profiles = _resolve_fleet_profiles(profile)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Operational error: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    resolved_ruleset_path = resolve_ruleset_path(ruleset)
    if ruleset_trust_manifest is not None:
        try:
            verify_ruleset_with_manifest(
                ruleset_path=resolved_ruleset_path,
                manifest_path=ruleset_trust_manifest.expanduser().resolve(strict=False),
                require_signatures=require_ruleset_signatures,
            )
        except (OSError, ValueError) as exc:
            console.print(f"[red]Operational error: {exc}[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    bundles = []
    try:
        for selected_profile in selected_profiles:
            bundles.append(
                run_scan(
                    selected_profile,
                    ruleset_path=resolved_ruleset_path,
                    policy_paths=policy_path,
                    suppression_paths=suppression_path,
                    intel_store_dir=intel_store_dir,
                    intel_snapshot_id=intel_snapshot_id,
                )
            )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Operational error: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    report = build_fleet_report(bundles)
    payload = render_fleet_json(report)

    if json_output:
        typer.echo(payload)
    elif output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(payload, encoding="utf-8")
            console.print(f"Fleet report written to: {output}")
        except OSError as exc:
            console.print(f"[red]Operational error writing fleet output: {exc}[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc
    else:
        console.print(f"Profiles scanned: {report.aggregate.profiles_total}")
        console.print(f"Findings total: {report.aggregate.findings_total}")
        console.print(f"High findings: {report.aggregate.findings_high_count}")

    raise typer.Exit(
        code=EXIT_HIGH_FINDINGS if report.aggregate.findings_high_count > 0 else EXIT_OK
    )


app.add_typer(profiles_app, name="profiles")
app.add_typer(snapshot_app, name="snapshot")
app.add_typer(intel_app, name="intel")
app.add_typer(fleet_app, name="fleet")
app.add_typer(suppression_app, name="suppression")
app.add_typer(bundle_app, name="bundle")


@snapshot_app.command("diff")
def snapshot_diff(
    before: Path = typer.Option(
        ..., "--before", help="Path to baseline snapshot JSON."
    ),
    after: Path = typer.Option(
        ..., "--after", help="Path to current snapshot JSON."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit snapshot diff JSON to stdout."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write snapshot diff JSON to this path."
    ),
) -> None:
    """Compare two deterministic snapshots."""
    if json_output and output is not None:
        console.print("[red]Operational error: --json and --output cannot be combined.[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    try:
        before_snapshot = load_scan_snapshot(before)
        after_snapshot = load_scan_snapshot(after)
        diff = build_scan_snapshot_diff(before_snapshot, after_snapshot)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Operational error: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    if json_output:
        typer.echo(render_snapshot_diff_json(diff))
    elif output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(render_snapshot_diff_json(diff), encoding="utf-8")
            console.print(f"Snapshot diff written to: {output}")
            render_snapshot_diff_summary(console, diff)
        except OSError as exc:
            console.print(f"[red]Operational error writing snapshot diff: {exc}[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc
    else:
        render_snapshot_diff_summary(console, diff)

    raise typer.Exit(code=EXIT_HIGH_FINDINGS if diff.summary.drift_detected else EXIT_OK)


@intel_app.command("sync")
def intel_sync(
    source: list[str] = typer.Option(
        ...,
        "--source",
        help="Source mapping in name=origin format; repeatable.",
    ),
    store_dir: Path | None = typer.Option(
        None,
        "--store-dir",
        help="Override intelligence store directory.",
    ),
    normalize_json: bool = typer.Option(
        True,
        "--normalize-json/--no-normalize-json",
        help="Canonicalize JSON source payloads before checksuming and storage.",
    ),
    allow_insecure_http: bool = typer.Option(
        False,
        "--allow-insecure-http",
        help=(
            "Allow plaintext HTTP source URLs for explicit trusted lab mirrors. "
            "HTTPS remains the default."
        ),
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit synced manifest JSON to stdout.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Write synced manifest JSON to this path.",
    ),
) -> None:
    """Fetch and persist intelligence source snapshots."""
    if json_output and output is not None:
        console.print("[red]Operational error: --json and --output cannot be combined.[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR)

    try:
        result = sync_sources(
            source_specs=source,
            store_dir=store_dir,
            normalize_json=normalize_json,
            cwd=Path.cwd(),
            allow_insecure_http=allow_insecure_http,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Operational error: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    payload = result.manifest.model_dump_json(indent=2)
    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(payload + "\n", encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Operational error writing intel manifest: {exc}[/red]")
            raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    if json_output:
        typer.echo(payload)
        raise typer.Exit(code=EXIT_OK)

    console.print(f"Intel snapshot id: {result.manifest.snapshot_id}")
    console.print(f"Store directory: {result.store_dir}")
    console.print(f"Manifest path: {result.manifest_path}")
    if output is not None:
        console.print(f"Manifest copy written to: {output}")

    table = Table(title="Synced Intel Sources")
    table.add_column("Source")
    table.add_column("Origin")
    table.add_column("Bytes", justify="right")
    table.add_column("SHA256")
    for item in result.manifest.sources:
        table.add_row(
            item.name,
            item.origin,
            str(item.size_bytes),
            item.sha256,
        )
    console.print(table)
    raise typer.Exit(code=EXIT_OK)


@suppression_app.command("audit")
def suppression_audit(
    suppression_path: list[Path] = typer.Option(
        ...,
        "--suppression-path",
        help="Apply suppression policy file(s); repeatable.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON audit report to stdout."
    ),
) -> None:
    """Audit suppression policies for governance violations and aging."""
    import json
    from datetime import UTC, datetime

    from foxclaw.rules.suppressions import _load_suppression_sources
    
    now = datetime.now(UTC)
    
    from typing import Any
    
    try:
        source_entries, legacy_count = _load_suppression_sources(suppression_path)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Audit failed: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc

    results: dict[str, Any] = {
        "files_scanned": len(set(path.expanduser().resolve().as_posix() for path in suppression_path)),
        "total_entries": len(source_entries),
        "legacy_schema_count": legacy_count,
        "expired": [],
        "expiring_soon": [],
        "duplicate_ids": [],
    }

    seen_ids = set()
    for source in source_entries:
        entry = source.entry
        if entry.id:
            if entry.id in seen_ids:
                results["duplicate_ids"].append({"id": entry.id, "source": source.source_path.as_posix()})
            seen_ids.add(entry.id)
            
        delta = entry.expires_at.astimezone(UTC) - now
        
        info: dict[str, Any] = {
            "id": entry.id,
            "rule_id": entry.rule_id,
            "owner": entry.owner,
            "expires_at": entry.expires_at.isoformat(),
            "source": source.source_path.as_posix()
        }
        
        if delta.total_seconds() < 0:
            results["expired"].append(info)
        elif delta.days <= 30:
            info["days_remaining"] = delta.days
            results["expiring_soon"].append(info)

    if json_output:
        typer.echo(json.dumps(results, indent=2))
        raise typer.Exit(code=EXIT_HIGH_FINDINGS if results["expired"] else EXIT_OK)

    table = Table(title="Suppression Governance Audit")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Files scanned", str(results["files_scanned"]))
    table.add_row("Total entries", str(results["total_entries"]))
    table.add_row("Legacy v1.0.0 schemas", str(results["legacy_schema_count"]))
    table.add_row("Expired entries", f"[red]{len(results['expired'])}[/red]" if results["expired"] else "0")
    table.add_row("Expiring <= 30d", f"[yellow]{len(results['expiring_soon'])}[/yellow]" if results["expiring_soon"] else "0")
    table.add_row("Duplicate IDs", f"[red]{len(results['duplicate_ids'])}[/red]" if results["duplicate_ids"] else "0")
    console.print(table)
    
    if results["expired"] or results["duplicate_ids"]:
        raise typer.Exit(code=EXIT_HIGH_FINDINGS)
    raise typer.Exit(code=EXIT_OK)


@bundle_app.command("fetch")
def bundle_fetch(
    url: str = typer.Argument(..., help="Remote URL of the signed ruleset bundle archive."),
    output_path: Path = typer.Option(
        ..., "--output", "-o", help="Path to write the bundle tarball."
    ),
    allow_insecure_http: bool = typer.Option(
        False, "--allow-insecure-http", help="Allow unsafe HTTP transport."
    ),
) -> None:
    """Download a ruleset bundle archive without verification or extraction."""
    from foxclaw.rules.bundle import fetch_bundle
    
    console.print(f"[blue]Fetching bundle from: {url}[/blue]")
    try:
        fetch_bundle(url=url, dest_path=output_path, allow_insecure_http=allow_insecure_http)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Fetch failed: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc
        
    console.print(f"[green]Successfully downloaded bundle to {output_path}[/green]")


@bundle_app.command("install")
def bundle_install(
    archive: Path = typer.Argument(..., help="Path to the downloaded bundle tarball."),
    keyring: Path = typer.Option(..., "--keyring", help="Path to the trusted keyring manifest."),
    key_id: str = typer.Option(..., "--key-id", help="Required keyring key_id to verify the manifest signature."),
    dest: Path = typer.Option(..., "--dest", help="Directory to unpack the validated bundle into."),
) -> None:
    """Verify an external bundle's signatures and unpack it locally."""
    from foxclaw.rules.bundle import verify_and_unpack_bundle
    
    console.print("[blue]Verifying and unpacking external ruleset bundle...[/blue]")
    try:
        manifest = verify_and_unpack_bundle(
            archive_path=archive,
            install_dir=dest,
            key_id=key_id,
            keyring_path=keyring,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]Bundle installation failed: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc
        
    console.print(f"[green]Successfully installed '{manifest.bundle_name}' (v{manifest.bundle_version}) to {dest}[/green]")


@bundle_app.command("verify")
def bundle_verify(
    archive: Path = typer.Argument(..., help="Path to the downloaded bundle tarball."),
    keyring: Path = typer.Option(..., "--keyring", help="Path to the trusted keyring manifest."),
    key_id: str = typer.Option(..., "--key-id", help="Required keyring key_id to verify the manifest signature."),
) -> None:
    """Verify an external bundle's signature strictly without unpacking it."""
    import shutil
    import tempfile

    from foxclaw.rules.bundle import verify_and_unpack_bundle
    
    tmp_path = Path(tempfile.mkdtemp())
    try:
        manifest = verify_and_unpack_bundle(
            archive_path=archive,
            install_dir=tmp_path,
            key_id=key_id,
            keyring_path=keyring,
        )
        console.print(f"[green]Bundle '{manifest.bundle_name}' (v{manifest.bundle_version}) signature verification passed.[/green]")
    except (OSError, ValueError) as exc:
        console.print(f"[red]Bundle verification failed: {exc}[/red]")
        raise typer.Exit(code=EXIT_OPERATIONAL_ERROR) from exc
    finally:
        shutil.rmtree(tmp_path, ignore_errors=True)

def _resolve_fleet_profiles(profile_paths: list[Path] | None) -> list[FirefoxProfile]:
    if profile_paths:
        deduped_paths: list[Path] = []
        seen_paths: set[Path] = set()
        for path in profile_paths:
            resolved = path.expanduser().resolve()
            if resolved in seen_paths:
                continue
            deduped_paths.append(resolved)
            seen_paths.add(resolved)

        return [
            _build_profile_override(path, profile_id=_manual_profile_id(path))
            for path in sorted(deduped_paths, key=lambda item: item.as_posix())
        ]

    report = discover_profiles()
    if not report.profiles:
        raise ValueError("no Firefox profiles discovered for fleet aggregation.")

    deduped_profiles: list[FirefoxProfile] = []
    seen_discovered_paths: set[Path] = set()
    for discovered in sorted(
        report.profiles,
        key=lambda item: (
            item.path.expanduser().resolve().as_posix(),
            item.profile_id,
        ),
    ):
        resolved = discovered.path.expanduser().resolve()
        if resolved in seen_discovered_paths:
            continue
        deduped_profiles.append(discovered)
        seen_discovered_paths.add(resolved)
    return deduped_profiles


def _build_profile_override(profile_path: Path, *, profile_id: str = "manual") -> FirefoxProfile:
    resolved = profile_path.expanduser().resolve()
    lock_files = [
        name for name in ("parent.lock", "lock") if (resolved / name).exists()
    ]
    return FirefoxProfile(
        profile_id=profile_id,
        name=resolved.name or "manual-profile",
        path=resolved,
        is_relative=False,
        default_flag=False,
        lock_detected=bool(lock_files),
        lock_files=lock_files,
        selected=True,
        selection_reason="Selected explicitly via --profile.",
    )


def _manual_profile_id(path: Path) -> str:
    digest = hashlib.sha256(path.as_posix().encode("utf-8")).hexdigest()[:12]
    return f"manual-{digest}"


if __name__ == "__main__":
    app()
