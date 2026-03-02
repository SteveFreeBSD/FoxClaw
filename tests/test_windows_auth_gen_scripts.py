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
    assert "require.resolve('better-sqlite3',{paths:[process.argv[1]]})" in payload


def test_generate_profiles_script_drops_stale_foxclaw_gen_guidance() -> None:
    payload = Path("scripts/windows_auth_gen/generate_profiles.ps1").read_text(encoding="utf-8")
    assert "foxclaw-gen directory" not in payload
    assert "npm ci --prefix scripts/windows_auth_gen" in payload


def test_mutate_profile_script_avoids_unseeded_entropy_sources() -> None:
    payload = Path("scripts/windows_auth_gen/mutate_profile.mjs").read_text(encoding="utf-8")
    assert "crypto.randomBytes" not in payload
    assert "crypto.randomUUID" not in payload
    assert "Date.now()" not in payload
    assert 'let seed = "424242";' in payload
    assert "initializeRunContext(seed);" in payload
    assert "function seededUuid(rng)" in payload


def test_mutate_profile_script_hashes_real_config_surfaces() -> None:
    payload = Path("scripts/windows_auth_gen/mutate_profile.mjs").read_text(encoding="utf-8")
    assert "function computeConfigHash()" in payload
    for snippet in (
        "historyUrls:",
        "searchTerms:",
        "downloadNames:",
        "weakPasswords:",
        "scenarioPickList:",
        "scenarioNames:",
        "cveExpectedRules:",
    ):
        assert snippet in payload


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


def test_windows_auth_gen_package_manifest_pins_better_sqlite3() -> None:
    package_payload = json.loads(
        Path("scripts/windows_auth_gen/package.json").read_text(encoding="utf-8")
    )
    assert package_payload["private"] is True
    assert package_payload["engines"]["node"] == ">=16"
    assert package_payload["dependencies"]["better-sqlite3"] == "11.10.0"


def _node_with_better_sqlite3() -> str:
    node_bin = shutil.which("node")
    if node_bin is None:
        pytest.skip("node is not installed in this environment")
    generator_dir = Path("scripts/windows_auth_gen").resolve()
    probe = subprocess.run(
        [
            node_bin,
            "-e",
            "const mod=require.resolve('better-sqlite3',{paths:[process.argv[1]]}); require(mod)",
            str(generator_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        pytest.skip("better-sqlite3 is not installed for mutate_profile runtime checks")
    return node_bin


def _run_mutate_profile(
    node_bin: str,
    profile_dir: Path,
    *,
    scenario: str,
    seed: str,
    profile_name: str,
) -> dict[str, object]:
    manifest_path = profile_dir / "foxclaw-sim-metadata.json"
    mutate_cmd = [
        node_bin,
        "scripts/windows_auth_gen/mutate_profile.mjs",
        str(profile_dir),
        "--scenario",
        scenario,
        "--seed",
        seed,
        "--profile-name",
        profile_name,
        "--manifest-out",
        str(manifest_path),
        "--fast",
    ]
    mutate_result = subprocess.run(mutate_cmd, check=False, capture_output=True, text=True)
    assert mutate_result.returncode == 0, mutate_result.stderr + mutate_result.stdout
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def test_mutate_profile_same_seed_produces_stable_manifest(tmp_path: Path) -> None:
    node_bin = _node_with_better_sqlite3()
    payloads: list[dict[str, object]] = []
    for index in range(2):
        profile_dir = tmp_path / f"seeded-{index}"
        shutil.copytree("tests/fixtures/firefox_profile", profile_dir)
        payload = _run_mutate_profile(
            node_bin,
            profile_dir,
            scenario="credential_reuse",
            seed="7300",
            profile_name="deterministic-profile",
        )
        payload["profile_dir"] = "<normalized>"
        payloads.append(payload)

    assert payloads[0] == payloads[1]
    assert payloads[0]["runtime_seconds"] == 0
    assert payloads[0]["started_at_utc"] == payloads[0]["completed_at_utc"]


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

    _run_mutate_profile(
        node_bin,
        profile_dir,
        scenario=scenario,
        seed="7300",
        profile_name=scenario,
    )

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
