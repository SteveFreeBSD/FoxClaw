from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

CVE_EXPECTED_STRICT_RULES: dict[str, str] = {
    "cve_sandbox_escape": "FC-STRICT-COOKIE-001",
    "cve_extension_abuse": "FC-STRICT-PKCS11-001",
    "cve_session_hijack": "FC-STRICT-SESSION-001",
    "cve_cert_injection": "FC-STRICT-CERT-001",
    "cve_handler_hijack": "FC-STRICT-HANDLER-001",
    "cve_hsts_downgrade": "FC-STRICT-HSTS-001",
    "cve_search_hijack": "FC-STRICT-SEARCH-001",
}


def test_mutate_profile_script_has_valid_node_syntax() -> None:
    node_bin = shutil.which("node")
    if node_bin is None:
        pytest.skip("node is not installed in this environment")

    script = Path("scripts/windows_auth_gen/mutate_profile.mjs")
    result = subprocess.run(
        [node_bin, "--check", str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout


def test_generate_profiles_script_passes_scenario_and_seed_to_mutator() -> None:
    script_path = Path("scripts/windows_auth_gen/generate_profiles.ps1")
    payload = script_path.read_text(encoding="utf-8")
    assert '"--scenario", $work.ScenarioName' in payload or '"--scenario", $scenarioName' in payload
    assert '"--seed", $work.ProfileSeed' in payload or '"--seed", $profileSeed' in payload
    assert "foxclaw-sim-metadata.json" in payload


def test_mutate_profile_script_seeds_credential_artifacts_for_scan_signals() -> None:
    script_path = Path("scripts/windows_auth_gen/mutate_profile.mjs")
    payload = script_path.read_text(encoding="utf-8")
    assert "logins.json" in payload
    assert "potentiallyVulnerablePasswords" in payload
    assert "dismissedBreachAlertsByLoginGUID" in payload
    assert "expected_scan_signals" in payload


def test_windows_generator_scripts_expose_cve_scenarios() -> None:
    mutate_payload = Path("scripts/windows_auth_gen/mutate_profile.mjs").read_text(encoding="utf-8")
    ps_payload = Path("scripts/windows_auth_gen/generate_profiles.ps1").read_text(encoding="utf-8")
    for scenario, expected_rule_id in CVE_EXPECTED_STRICT_RULES.items():
        assert scenario in mutate_payload
        assert scenario in ps_payload
        assert expected_rule_id in mutate_payload


def _node_with_better_sqlite3() -> str:
    node_bin = shutil.which("node")
    if node_bin is None:
        pytest.skip("node is not installed in this environment")
    probe = subprocess.run(
        [node_bin, "-e", "require('better-sqlite3')"],
        check=False,
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        pytest.skip("better-sqlite3 is not installed for mutate_profile runtime checks")
    return node_bin


@pytest.mark.parametrize(
    ("scenario", "expected_rule_id"),
    tuple(CVE_EXPECTED_STRICT_RULES.items()),
)
def test_mutate_profile_cve_scenarios_trigger_expected_strict_finding(
    tmp_path: Path,
    scenario: str,
    expected_rule_id: str,
) -> None:
    node_bin = _node_with_better_sqlite3()
    profile_dir = tmp_path / scenario
    shutil.copytree("tests/fixtures/firefox_profile", profile_dir)

    mutate_cmd = [
        node_bin,
        "scripts/windows_auth_gen/mutate_profile.mjs",
        str(profile_dir),
        "--scenario",
        scenario,
        "--seed",
        "7300",
        "--profile-name",
        scenario,
        "--fast",
    ]
    mutate_result = subprocess.run(mutate_cmd, check=False, capture_output=True, text=True)
    assert mutate_result.returncode == 0, mutate_result.stderr + mutate_result.stdout

    scan_cmd = [
        sys.executable,
        "-m",
        "foxclaw",
        "scan",
        "--profile",
        str(profile_dir),
        "--ruleset",
        "foxclaw/rulesets/strict.yml",
        "--json",
    ]
    scan_result = subprocess.run(scan_cmd, check=False, capture_output=True, text=True)
    assert scan_result.returncode == 2, scan_result.stderr + scan_result.stdout
    payload = json.loads(scan_result.stdout)
    findings = payload.get("findings")
    assert isinstance(findings, list)
    rule_ids: list[str] = sorted(
        {
            rule_id.strip()
            for item in findings
            if isinstance(item, dict)
            for rule_id in [
                item.get("id") if isinstance(item.get("id"), str) else item.get("rule_id")
            ]
            if isinstance(rule_id, str) and rule_id.strip()
        }
    )
    assert expected_rule_id in rule_ids
