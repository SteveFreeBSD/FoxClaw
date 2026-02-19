"""CLI entrypoint for foxclaw."""

from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from foxclaw.report.jsonout import render_scan_json
from foxclaw.report.text import render_scan_summary
from foxclaw.profiles import discover_profiles
from foxclaw.scan import run_scan

app = typer.Typer(help="foxclaw CLI")
profiles_app = typer.Typer(help="Profile commands")
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
        raise typer.Exit(code=0)

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
    raise typer.Exit(code=0)


@app.command("scan")
def scan(
    json_output: bool = typer.Option(
        False, "--json", help="Print JSON evidence to stdout."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write JSON evidence to this path."
    ),
) -> None:
    """Run read-only scan."""
    report = discover_profiles()
    selected_profile = next((p for p in report.profiles if p.selected), None)
    if selected_profile is None:
        console.print("[red]Operational error: no Firefox profile selected.[/red]")
        if report.searched_dirs:
            console.print("Searched directories:")
            for search_dir in report.searched_dirs:
                console.print(f"  - {search_dir}")
        raise typer.Exit(code=1)

    try:
        evidence = run_scan(selected_profile)
    except OSError as exc:
        console.print(f"[red]Operational error: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    json_payload = render_scan_json(evidence)
    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json_payload, encoding="utf-8")
        except OSError as exc:
            console.print(f"[red]Operational error writing output: {exc}[/red]")
            raise typer.Exit(code=1) from exc

    if json_output and output is None:
        typer.echo(json_payload)
    elif not json_output:
        render_scan_summary(console, evidence)
        if output is not None:
            console.print(f"JSON report written to: {output}")

    raise typer.Exit(code=2 if evidence.summary.high_findings_count > 0 else 0)


@app.command("snapshot")
def snapshot() -> None:
    """Create snapshot."""
    typer.echo("TODO")
    raise typer.Exit(code=0)


@app.command("diff")
def diff() -> None:
    """Compare current state with snapshot."""
    typer.echo("TODO")
    raise typer.Exit(code=0)


@app.command("plan")
def plan() -> None:
    """Generate remediation plan."""
    typer.echo("TODO")
    raise typer.Exit(code=0)


@app.command("apply")
def apply() -> None:
    """Apply remediation plan."""
    typer.echo("TODO")
    raise typer.Exit(code=0)


app.add_typer(profiles_app, name="profiles")


if __name__ == "__main__":
    app()
