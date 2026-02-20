"""CLI entrypoint for foxclaw."""

from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from foxclaw.intel.sync import sync_sources
from foxclaw.profiles import FirefoxProfile, discover_profiles
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
from foxclaw.scan import detect_active_profile_reason, resolve_ruleset_path, run_scan

EXIT_OK = 0
EXIT_OPERATIONAL_ERROR = 1
EXIT_HIGH_FINDINGS = 2

app = typer.Typer(help="FoxClaw: deterministic Firefox security posture scanner.")
profiles_app = typer.Typer(help="Firefox profile discovery commands.")
snapshot_app = typer.Typer(help="Snapshot baseline and drift commands.")
intel_app = typer.Typer(help="Threat intelligence synchronization commands.")
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


app.add_typer(profiles_app, name="profiles")
app.add_typer(snapshot_app, name="snapshot")
app.add_typer(intel_app, name="intel")


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


def _build_profile_override(profile_path: Path) -> FirefoxProfile:
    resolved = profile_path.expanduser().resolve()
    lock_files = [
        name for name in ("parent.lock", "lock") if (resolved / name).exists()
    ]
    return FirefoxProfile(
        profile_id="manual",
        name=resolved.name or "manual-profile",
        path=resolved,
        is_relative=False,
        default_flag=False,
        lock_detected=bool(lock_files),
        lock_files=lock_files,
        selected=True,
        selection_reason="Selected explicitly via --profile.",
    )


if __name__ == "__main__":
    app()
