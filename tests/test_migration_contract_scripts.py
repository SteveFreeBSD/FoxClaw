from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_migration_contract_fixture_check_passes() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/generate_migration_contract_fixtures.py",
            "--check",
            "--python-cmd",
            f"{sys.executable} -m foxclaw",
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_migration_contract_verify_python_baseline(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_migration_contract_engine.py",
            "--engine-cmd",
            f"{sys.executable} -m foxclaw",
            "--engine-label",
            "python",
            "--scenario",
            "profile_baseline",
            "--output-dir",
            str(tmp_path / "contract-verify"),
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
