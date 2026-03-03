from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_ws_floor_sync.py"


def test_ws_floor_sync_script_passes_and_fails(tmp_path: Path) -> None:
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "WORKSLICES.md").write_text(
        "- Current direction: WS-83, WS-84, and WS-85 stay accepted in the validated Python baseline for this branch.\n",
        encoding="utf-8",
    )
    (docs_dir / "PREMERGE_READINESS.md").write_text(
        "1. **WS-66 / WS-85 evidence review**: this baseline remains accepted.\n",
        encoding="utf-8",
    )

    pass_result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    assert pass_result.returncode == 0, pass_result.stdout + pass_result.stderr
    assert "[ws-floor-sync] OK ws_floor=WS-85" in pass_result.stdout

    (docs_dir / "PREMERGE_READINESS.md").write_text(
        "1. **WS-66 / WS-84 evidence review**: this baseline remains accepted.\n",
        encoding="utf-8",
    )
    fail_result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    assert fail_result.returncode == 1
    assert "workslices=WS-85 premerge=WS-84" in fail_result.stdout
