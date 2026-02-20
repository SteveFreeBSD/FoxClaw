from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from foxclaw.cli import app
from foxclaw.intel.sync import sync_sources
from typer.testing import CliRunner

INTEL_FIXTURE = Path("tests/fixtures/intel/mozilla_firefox_advisories.v1.json")


def _create_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def _prepare_profile(profile_dir: Path, *, last_version: str) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    (profile_dir / "compatibility.ini").write_text(
        "\n".join(
            [
                "[Compatibility]",
                f"LastVersion={last_version}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")


def _write_empty_ruleset(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "name: empty",
                "version: 1.0.0",
                "rules: []",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_scan_with_intel_snapshot_emits_correlated_cve_finding(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    sync_result = sync_sources(
        source_specs=[f"mozilla={INTEL_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="135.0_20260201000000/20260201000000")
    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            sync_result.manifest.snapshot_id,
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["summary"]["intel_matches_count"] == 1
    assert payload["intel"]["enabled"] is True
    assert payload["intel"]["snapshot_id"] == sync_result.manifest.snapshot_id
    assert payload["intel"]["profile_firefox_version"] == "135.0"
    assert {finding["id"] for finding in payload["findings"]} == {"FC-INTEL-CVE-2026-0001"}


def test_scan_with_intel_snapshot_has_no_findings_when_version_not_affected(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    sync_sources(
        source_specs=[f"mozilla={INTEL_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="136.0_20260201000000/20260201000000")
    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "latest",
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["intel_matches_count"] == 0
    assert payload["findings"] == []


def test_scan_with_unknown_intel_snapshot_id_fails_operationally(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    sync_sources(
        source_specs=[f"mozilla={INTEL_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="135.0_20260201000000/20260201000000")
    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "deadbeef",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "intel snapshot id not found" in result.stdout
