from __future__ import annotations

import json
import shutil
from pathlib import Path

from foxclaw.cli import app
from jsonschema import Draft4Validator
from typer.testing import CliRunner

TESTBED_ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "testbed"
TESTBED_RULESET = TESTBED_ROOT / "rulesets" / "integration.yml"
TESTBED_POLICY = TESTBED_ROOT / "policies" / "disable_telemetry.json"

def _load_official_sarif_schema() -> dict[str, object]:
    path = Path(__file__).resolve().parents[1] / "tests" / "schemas" / "sarif-schema-2.1.0.json"
    return json.loads(path.read_text(encoding="utf-8"))

def test_json_and_sarif_are_deterministic(tmp_path: Path) -> None:
    profile_src = TESTBED_ROOT / "profile_policy_present"
    profile = tmp_path / "profile_policy_present"
    shutil.copytree(profile_src, profile)
    for file_path in profile.rglob("*"):
        if file_path.is_file():
            file_path.chmod(0o600)

    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    json_a = dir_a / "scan.json"
    sarif_a = dir_a / "scan.sarif"

    json_b = dir_b / "scan.json"
    sarif_b = dir_b / "scan.sarif"

    runner = CliRunner()
    base_cmd = [
        "scan",
        "--profile", str(profile),
        "--ruleset", str(TESTBED_RULESET),
        "--policy-path", str(TESTBED_POLICY),
        "--deterministic",
    ]

    # Run from dir_a to see if CWD leaks into absolute paths
    res_a = runner.invoke(app, [*base_cmd, "--output", str(json_a), "--sarif-out", str(sarif_a)])

    # Run from dir_b
    res_b = runner.invoke(app, [*base_cmd, "--output", str(json_b), "--sarif-out", str(sarif_b)])

    assert res_a.exit_code == 0
    assert res_b.exit_code == 0

    assert json_a.read_text(encoding="utf-8") == json_b.read_text(encoding="utf-8")
    assert sarif_a.read_text(encoding="utf-8") == sarif_b.read_text(encoding="utf-8")

    # Double check SARIF validity against the official schema
    sarif_payload = json.loads(sarif_a.read_text(encoding="utf-8"))
    Draft4Validator(_load_official_sarif_schema()).validate(sarif_payload)
