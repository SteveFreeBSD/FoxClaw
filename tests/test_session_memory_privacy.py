from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_script_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_memory_scripts_default_to_local_artifacts() -> None:
    session_memory = _load_script_module(
        ROOT / "scripts" / "session_memory.py",
        "session_memory_privacy_session",
    )
    memory_index = _load_script_module(
        ROOT / "scripts" / "memory_index.py",
        "session_memory_privacy_index",
    )
    memory_query = _load_script_module(
        ROOT / "scripts" / "memory_query.py",
        "session_memory_privacy_query",
    )

    expected_root = ROOT / "artifacts" / "session_memory"
    assert session_memory.JOURNAL_PATH == expected_root / "SESSION_MEMORY.jsonl"
    assert session_memory.DOC_PATH == expected_root / "SESSION_MEMORY.md"
    assert memory_index.SOURCE_JSONL == expected_root / "SESSION_MEMORY.jsonl"
    assert memory_index.DB_PATH == expected_root / "index.sqlite"
    assert memory_query.DB_PATH == expected_root / "index.sqlite"


def test_session_memory_scripts_support_local_override(tmp_path: Path) -> None:
    memory_root = tmp_path / "local-memory"
    env = os.environ.copy()
    env["FOXCLAW_SESSION_MEMORY_DIR"] = str(memory_root)

    checkpoint = subprocess.run(
        [
            sys.executable,
            "scripts/session_memory.py",
            "checkpoint",
            "--focus",
            "privacy-test",
            "--next",
            "next-step",
            "--risks",
            "none",
            "--decisions",
            "local-only",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert checkpoint.returncode == 0, checkpoint.stderr + checkpoint.stdout

    build = subprocess.run(
        [sys.executable, "scripts/memory_index.py", "build"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert build.returncode == 0, build.stderr + build.stdout

    query = subprocess.run(
        [sys.executable, "scripts/memory_query.py", '"privacy-test"', "--limit", "1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert query.returncode == 0, query.stderr + query.stdout
    assert "privacy-test" in query.stdout
    assert (memory_root / "SESSION_MEMORY.jsonl").is_file()
    assert (memory_root / "SESSION_MEMORY.md").is_file()
    assert (memory_root / "index.sqlite").is_file()
