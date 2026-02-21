from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_synth_profiles_emits_metadata_and_required_files(tmp_path: Path) -> None:
    output_dir = tmp_path / "synth"
    command = [
        sys.executable,
        "scripts/synth_profiles.py",
        "--count",
        "2",
        "--output-dir",
        str(output_dir),
        "--mode",
        "bootstrap",
        "--scenario",
        "consumer_default",
        "--seed",
        "100",
        "--mutation-budget",
        "1",
        "--max-mutation-severity",
        "low",
        "--quiet",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout

    profiles = sorted(output_dir.glob("*.synth-*"))
    assert len(profiles) == 2

    for profile in profiles:
        assert (profile / "prefs.js").exists()
        assert (profile / "places.sqlite").exists()
        assert (profile / "cookies.sqlite").exists()
        assert (profile / "metadata.json").exists()
        metadata = json.loads((profile / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["scenario"] == "consumer_default"
        assert metadata["generator_mode"] == "bootstrap"
        assert isinstance(metadata["mutations"], list)


def test_fuzz_profiles_emits_reproducible_metadata(tmp_path: Path) -> None:
    output_dir = tmp_path / "fuzz"
    command = [
        sys.executable,
        "scripts/fuzz_profiles.py",
        "--count",
        "2",
        "--output-dir",
        str(output_dir),
        "--mode",
        "chaos",
        "--scenario",
        "consumer_default",
        "--seed",
        "200",
        "--mutation-budget",
        "2",
        "--max-mutation-severity",
        "high",
        "--quiet",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout

    profiles = sorted(output_dir.glob("profile_*"))
    assert len(profiles) == 2

    first_metadata = json.loads((profiles[0] / "metadata.json").read_text(encoding="utf-8"))
    second_metadata = json.loads((profiles[1] / "metadata.json").read_text(encoding="utf-8"))

    assert first_metadata["seed"] == 200
    assert second_metadata["seed"] == 201
    assert first_metadata["scenario"] == "consumer_default"
    assert isinstance(first_metadata["mutations"], list)
    assert len(first_metadata["mutations"]) >= 1
