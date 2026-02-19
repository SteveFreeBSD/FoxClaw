from __future__ import annotations

import json
from pathlib import Path

from foxclaw.cli import app
from typer.testing import CliRunner


def test_snapshot_diff_exit_zero_when_no_drift(tmp_path: Path) -> None:
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    scan_result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "tests/fixtures/firefox_profile",
            "--ruleset",
            "foxclaw/rulesets/balanced.yml",
            "--snapshot-out",
            str(baseline),
        ],
    )
    assert scan_result.exit_code == 2
    current.write_text(baseline.read_text(encoding="utf-8"), encoding="utf-8")

    diff_result = runner.invoke(
        app,
        [
            "snapshot",
            "diff",
            "--before",
            str(baseline),
            "--after",
            str(current),
            "--json",
        ],
    )
    assert diff_result.exit_code == 0
    payload = json.loads(diff_result.stdout)
    assert payload["summary"]["drift_detected"] is False
    assert payload["summary"]["added_findings_count"] == 0
    assert payload["summary"]["removed_findings_count"] == 0
    assert payload["summary"]["changed_findings_count"] == 0


def test_snapshot_diff_exit_two_when_drift_detected(tmp_path: Path) -> None:
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    baseline_scan = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "tests/fixtures/firefox_profile",
            "--ruleset",
            "foxclaw/rulesets/balanced.yml",
            "--snapshot-out",
            str(baseline),
        ],
    )
    assert baseline_scan.exit_code == 2

    current_scan = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "tests/fixtures/firefox_profile",
            "--ruleset",
            "foxclaw/rulesets/strict.yml",
            "--snapshot-out",
            str(current),
        ],
    )
    assert current_scan.exit_code == 2

    diff_result = runner.invoke(
        app,
        [
            "snapshot",
            "diff",
            "--before",
            str(baseline),
            "--after",
            str(current),
            "--json",
        ],
    )
    assert diff_result.exit_code == 2
    payload = json.loads(diff_result.stdout)
    assert payload["summary"]["drift_detected"] is True
    assert (
        payload["summary"]["added_findings_count"]
        + payload["summary"]["removed_findings_count"]
        + payload["summary"]["changed_findings_count"]
    ) > 0


def test_snapshot_diff_exit_one_for_invalid_snapshot_file(tmp_path: Path) -> None:
    runner = CliRunner()
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"

    before.write_text("{not-json", encoding="utf-8")
    after.write_text("{}", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "snapshot",
            "diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--json",
        ],
    )
    assert result.exit_code == 1
