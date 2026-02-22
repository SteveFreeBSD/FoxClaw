from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_rust_parity_runner_passes_with_python_on_both_engines(tmp_path: Path) -> None:
    summary = tmp_path / "summary.json"
    output_dir = tmp_path / "out"
    cmd = [
        sys.executable,
        "scripts/rust_parity_runner.py",
        "--scenario",
        "profile_baseline",
        "--python-cmd",
        f"{sys.executable} -m foxclaw",
        "--rust-cmd",
        f"{sys.executable} -m foxclaw",
        "--output-dir",
        str(output_dir),
        "--json-out",
        str(summary),
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["cases_total"] == 1
    assert payload["cases_failed"] == 0
    assert payload["cases_passed"] == 1
    assert payload["results"][0]["status"] == "PASS"


def test_rust_parity_runner_fails_when_rust_command_missing(tmp_path: Path) -> None:
    summary = tmp_path / "summary.json"
    output_dir = tmp_path / "out"
    cmd = [
        sys.executable,
        "scripts/rust_parity_runner.py",
        "--scenario",
        "profile_baseline",
        "--python-cmd",
        f"{sys.executable} -m foxclaw",
        "--rust-cmd",
        str(tmp_path / "missing-rust-command"),
        "--output-dir",
        str(output_dir),
        "--json-out",
        str(summary),
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert result.returncode == 1

    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["cases_total"] == 1
    assert payload["cases_failed"] == 1
    issues = payload["results"][0]["issues"]
    assert any("launch failed" in issue for issue in issues)
