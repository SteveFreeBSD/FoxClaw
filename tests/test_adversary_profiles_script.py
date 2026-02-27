from __future__ import annotations

import json
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


def test_adversary_profiles_script_generates_summary_and_profiles(tmp_path: Path) -> None:
    output_dir = tmp_path / "adversary"
    command = [
        sys.executable,
        "scripts/adversary_profiles.py",
        "--output-dir",
        str(output_dir),
        "--count-per-scenario",
        "1",
        "--scenario",
        "compromised",
        "--seed",
        "1234",
        "--mutation-budget",
        "1",
        "--max-mutation-severity",
        "high",
        "--quiet",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout

    summary_path = output_dir / "adversary-summary.json"
    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    assert summary["profiles_total"] == 1
    assert summary["count_per_scenario"] == 1
    assert summary["scenarios"] == ["compromised"]
    assert summary["operational_failure_count"] == 0
    assert summary["clean_count"] + summary["findings_count"] == 1
    assert isinstance(summary["per_profile"], list)
    assert len(summary["per_profile"]) == 1

    profile_name = summary["per_profile"][0]["profile"]
    profile_dir = output_dir / profile_name
    assert profile_dir.is_dir()
    assert (profile_dir / "metadata.json").exists()


@pytest.mark.parametrize(
    ("scenario", "expected_rule_id"),
    tuple(CVE_EXPECTED_STRICT_RULES.items()),
)
def test_adversary_profiles_cve_scenarios_trigger_expected_finding(
    tmp_path: Path,
    scenario: str,
    expected_rule_id: str,
) -> None:
    output_dir = tmp_path / scenario
    command = [
        sys.executable,
        "scripts/adversary_profiles.py",
        "--output-dir",
        str(output_dir),
        "--count-per-scenario",
        "1",
        "--scenario",
        scenario,
        "--seed",
        "9100",
        "--mutation-budget",
        "0",
        "--max-mutation-severity",
        "low",
        "--quiet",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout

    summary = json.loads((output_dir / "adversary-summary.json").read_text(encoding="utf-8"))
    assert summary["scenarios"] == [scenario]
    assert summary["profiles_total"] == 1
    assert summary["operational_failure_count"] == 0

    profile = summary["per_profile"][0]
    assert profile["exit_code"] == 2
    assert profile["expected_rule_id"] == expected_rule_id
    assert profile["expected_rule_matched"] is True
    assert expected_rule_id in profile["finding_rule_ids"]
