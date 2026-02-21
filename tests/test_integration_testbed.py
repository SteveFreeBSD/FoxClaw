from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from foxclaw.cli import app
from jsonschema import Draft4Validator
from typer.testing import CliRunner

pytestmark = pytest.mark.integration

TESTBED_ROOT = Path("tests/fixtures/testbed")
TESTBED_RULESET = TESTBED_ROOT / "rulesets" / "integration.yml"
TESTBED_POLICY = TESTBED_ROOT / "policies" / "disable_telemetry.json"
_MISSING_POLICY_FINDINGS = {"TB-POL-001", "TB-POL-002", "TB-POL-003", "TB-POL-004"}


def _load_official_sarif_schema() -> dict[str, object]:
    schema_path = Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module", autouse=True)
def _refresh_testbed_fixtures() -> None:
    subprocess.run(
        [sys.executable, "scripts/generate_testbed_fixtures.py", "--write"],
        check=True,
        cwd=Path(__file__).resolve().parents[1],
    )


@pytest.mark.parametrize(
    ("scenario", "with_policy_path", "expected_exit_code", "expected_finding_ids"),
    [
        ("profile_baseline", False, 0, _MISSING_POLICY_FINDINGS),
        (
            "profile_weak_perms",
            False,
            2,
            {"TB-FILE-001", *_MISSING_POLICY_FINDINGS},
        ),
        (
            "profile_sqlite_error",
            False,
            2,
            {"TB-SQL-001", *_MISSING_POLICY_FINDINGS},
        ),
        ("profile_policy_present", True, 0, set()),
        ("profile_userjs_override", False, 0, _MISSING_POLICY_FINDINGS),
        ("profile_third_party_xpi", False, 0, _MISSING_POLICY_FINDINGS),
    ],
)
def test_testbed_scenarios_emit_expected_findings(
    scenario: str,
    with_policy_path: bool,
    expected_exit_code: int,
    expected_finding_ids: set[str],
) -> None:
    profile = TESTBED_ROOT / scenario
    cmd = [
        "scan",
        "--profile",
        str(profile),
        "--ruleset",
        str(TESTBED_RULESET),
        "--json",
    ]
    if with_policy_path:
        cmd.extend(["--policy-path", str(TESTBED_POLICY)])

    runner = CliRunner()
    result = runner.invoke(app, cmd)
    assert result.exit_code == expected_exit_code

    payload = json.loads(result.stdout)
    observed_ids = {item["id"] for item in payload["findings"]}
    assert observed_ids == expected_finding_ids

    expected_high = sum(
        1
        for finding in payload["findings"]
        if finding["id"] in expected_finding_ids and finding["severity"] == "HIGH"
    )
    assert payload["summary"]["findings_high_count"] == expected_high
    expected_policies_found = 1 if with_policy_path else 0
    assert payload["summary"]["policies_found"] == expected_policies_found


def test_testbed_sarif_schema_and_snapshot_determinism(tmp_path: Path) -> None:
    profile = TESTBED_ROOT / "profile_policy_present"
    snapshot_a = tmp_path / "a.snapshot.json"
    snapshot_b = tmp_path / "b.snapshot.json"
    sarif_path = tmp_path / "scan.sarif"

    runner = CliRunner()
    base_cmd = [
        "scan",
        "--profile",
        str(profile),
        "--ruleset",
        str(TESTBED_RULESET),
        "--policy-path",
        str(TESTBED_POLICY),
    ]

    first = runner.invoke(
        app,
        [
            *base_cmd,
            "--snapshot-out",
            str(snapshot_a),
            "--sarif-out",
            str(sarif_path),
        ],
    )
    second = runner.invoke(
        app,
        [
            *base_cmd,
            "--snapshot-out",
            str(snapshot_b),
        ],
    )
    assert first.exit_code == 0
    assert second.exit_code == 0

    assert snapshot_a.read_text(encoding="utf-8") == snapshot_b.read_text(encoding="utf-8")

    sarif_payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    Draft4Validator(_load_official_sarif_schema()).validate(sarif_payload)
    assert sarif_payload["version"] == "2.1.0"
    assert sarif_payload["runs"][0]["tool"]["driver"]["name"] == "FoxClaw"


def test_testbed_fleet_aggregate_multi_profile_contract() -> None:
    profile_baseline = TESTBED_ROOT / "profile_baseline"
    profile_weak_perms = TESTBED_ROOT / "profile_weak_perms"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "fleet",
            "aggregate",
            "--profile",
            str(profile_baseline),
            "--profile",
            str(profile_weak_perms),
            "--ruleset",
            str(TESTBED_RULESET),
            "--json",
        ],
    )
    assert result.exit_code == 2

    payload = json.loads(result.stdout)
    assert payload["fleet_schema_version"] == "1.0.0"
    assert payload["aggregate"]["profiles_total"] == 2
    assert payload["aggregate"]["profiles_with_findings"] == 2
    assert payload["aggregate"]["profiles_with_high_findings"] == 1

    profile_summaries = payload["profiles"]
    assert len(profile_summaries) == 2
    assert payload["aggregate"]["findings_total"] == sum(
        item["summary"]["findings_total"] for item in profile_summaries
    )
    assert payload["aggregate"]["findings_high_count"] == sum(
        item["summary"]["findings_high_count"] for item in profile_summaries
    )
    assert payload["aggregate"]["findings_medium_count"] == sum(
        item["summary"]["findings_medium_count"] for item in profile_summaries
    )
    assert payload["aggregate"]["findings_info_count"] == sum(
        item["summary"]["findings_info_count"] for item in profile_summaries
    )
    assert len(payload["finding_records"]) == payload["aggregate"]["findings_total"]

    profile_paths = {item["identity"]["path"] for item in payload["profiles"]}
    assert profile_paths == {
        profile_baseline.resolve().as_posix(),
        profile_weak_perms.resolve().as_posix(),
    }

    profile_uids = {item["identity"]["profile_uid"] for item in payload["profiles"]}
    assert {item["profile_uid"] for item in payload["finding_records"]} <= profile_uids
    assert {"TB-FILE-001", *_MISSING_POLICY_FINDINGS} <= set(payload["aggregate"]["unique_rule_ids"])


def test_testbed_userjs_override_precedence_with_policy_path() -> None:
    profile = TESTBED_ROOT / "profile_userjs_override"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(TESTBED_RULESET),
            "--policy-path",
            str(TESTBED_POLICY),
            "--json",
        ],
    )
    assert result.exit_code == 0

    payload = json.loads(result.stdout)
    pref = payload["prefs"]["testbed.pref.override"]
    assert pref["value"] == "from-user"
    assert pref["source"] == "user.js"
    assert {item["id"] for item in payload["findings"]} == set()


def test_testbed_active_lock_profile_fails_with_require_quiet_profile() -> None:
    profile = TESTBED_ROOT / "profile_active_lock"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(TESTBED_RULESET),
            "--require-quiet-profile",
            "--json",
        ],
    )
    assert result.exit_code == 1
    assert "quiet profile required" in result.stdout


def test_testbed_third_party_xpi_manifest_parsed() -> None:
    profile = TESTBED_ROOT / "profile_third_party_xpi"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile),
            "--ruleset",
            str(TESTBED_RULESET),
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["extensions_found"] == 1

    ext = payload["extensions"]["entries"][0]
    assert ext["addon_id"] == "third-party@example.com"
    assert ext["manifest_status"] == "parsed"
    assert "<all_urls>" in ext["host_permissions"]
    assert "webRequest" in ext["permissions"]
