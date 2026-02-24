from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


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
