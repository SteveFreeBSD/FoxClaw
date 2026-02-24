from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


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
