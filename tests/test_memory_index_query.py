from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _write_checkpoint_log(path: Path, *, focus: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp_utc": "2026-02-27T18:00:00+00:00",
        "branch": "main",
        "commit": "deadbeefcafebabe",
        "focus": focus,
        "next_actions": "verify query output",
        "risks": "none",
        "decisions": "deterministic fixture",
    }
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def test_memory_index_build_and_query_succeeds_without_existing_journal(tmp_path: Path) -> None:
    index_path = tmp_path / "session-memory" / "index.sqlite"

    build = _run("scripts/memory_index.py", "build", "--index-path", str(index_path))
    assert build.returncode == 0, build.stdout + build.stderr
    assert "[memory-index] built" in build.stdout

    query = _run("scripts/memory_query.py", "fresh checkout", "--index-path", str(index_path))
    assert query.returncode == 0, query.stdout + query.stderr
    assert "[memory-query] no hits for: fresh checkout" in query.stdout


def test_memory_query_falls_back_when_fts_table_missing(tmp_path: Path) -> None:
    memory_dir = tmp_path / "session-memory"
    source_path = memory_dir / "SESSION_MEMORY.jsonl"
    index_path = memory_dir / "index.sqlite"
    _write_checkpoint_log(source_path, focus="fts regression")

    build = _run("scripts/memory_index.py", "build", "--index-path", str(index_path))
    assert build.returncode == 0, build.stdout + build.stderr

    with sqlite3.connect(index_path) as connection:
        connection.execute("DROP TABLE checkpoints_fts")
        connection.commit()

    query = _run(
        "scripts/memory_query.py",
        '"fts regression"',
        "--index-path",
        str(index_path),
        "--limit",
        "1",
    )
    assert query.returncode == 0, query.stdout + query.stderr
    assert "warning: checkpoints_fts unavailable; using LIKE fallback" in query.stdout
    assert "fts regression" in query.stdout


def test_memory_query_repair_rebuilds_missing_index(tmp_path: Path) -> None:
    memory_dir = tmp_path / "session-memory"
    source_path = memory_dir / "SESSION_MEMORY.jsonl"
    index_path = memory_dir / "index.sqlite"
    _write_checkpoint_log(source_path, focus="repair regression")

    query = _run(
        "scripts/memory_query.py",
        '"repair regression"',
        "--index-path",
        str(index_path),
        "--repair",
        "--limit",
        "1",
    )
    assert query.returncode == 0, query.stdout + query.stderr
    assert "[memory-query] repaired index:" in query.stdout
    assert "repair regression" in query.stdout


def test_memory_index_update_rebuilds_stale_fts_schema(tmp_path: Path) -> None:
    memory_dir = tmp_path / "session-memory"
    source_path = memory_dir / "SESSION_MEMORY.jsonl"
    index_path = memory_dir / "index.sqlite"
    _write_checkpoint_log(source_path, focus="update rebuild regression")

    build = _run("scripts/memory_index.py", "build", "--index-path", str(index_path))
    assert build.returncode == 0, build.stdout + build.stderr

    with sqlite3.connect(index_path) as connection:
        connection.execute("DROP TABLE checkpoints_fts")
        connection.commit()

    update = _run("scripts/memory_index.py", "update", "--index-path", str(index_path))
    assert update.returncode == 0, update.stdout + update.stderr
    assert "stale schema detected" in update.stdout
    assert "[memory-index] built" in update.stdout

    with sqlite3.connect(index_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert "checkpoints" in tables
    assert "checkpoints_fts" in tables
