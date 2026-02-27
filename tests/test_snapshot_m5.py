from __future__ import annotations

import json
from pathlib import Path

from foxclaw.cli import app
from typer.testing import CliRunner

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def test_snapshot_output_includes_expected_sections(tmp_path: Path) -> None:
    runner = CliRunner()
    snapshot_path = tmp_path / "snapshot.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            "tests/fixtures/firefox_profile",
            "--ruleset",
            "foxclaw/rulesets/balanced.yml",
            "--snapshot-out",
            str(snapshot_path),
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))

    assert payload["snapshot_schema_version"] == "1.0.0"
    assert payload["evidence_schema_version"] == "1.0.0"
    assert payload["ruleset"]["name"] == "balanced"
    assert payload["ruleset"]["version"] == "0.9.0"
    assert payload["ruleset"]["path"] == "foxclaw/rulesets/balanced.yml"
    assert payload["profile"]["path"] == "tests/fixtures/firefox_profile"
    assert len(payload["ruleset"]["sha256"]) == 64
    assert payload["summary"]["findings_total"] == len(payload["findings"])
    assert payload["high_findings"] == sorted(payload["high_findings"])
    assert "generated_at" not in payload

    sort_keys = [
        (_SEVERITY_ORDER[finding["severity"]], finding["id"], tuple(finding["evidence"]))
        for finding in payload["findings"]
    ]
    assert sort_keys == sorted(sort_keys)


def test_snapshot_output_is_deterministic_for_same_input(tmp_path: Path) -> None:
    runner = CliRunner()
    first_snapshot = tmp_path / "snapshot-a.json"
    second_snapshot = tmp_path / "snapshot-b.json"
    args = [
        "scan",
        "--profile",
        "tests/fixtures/firefox_profile",
        "--ruleset",
        "foxclaw/rulesets/balanced.yml",
    ]

    first_result = runner.invoke(app, [*args, "--snapshot-out", str(first_snapshot)])
    second_result = runner.invoke(app, [*args, "--snapshot-out", str(second_snapshot)])

    assert first_result.exit_code == 2
    assert second_result.exit_code == 2
    assert first_snapshot.read_text(encoding="utf-8") == second_snapshot.read_text(encoding="utf-8")
