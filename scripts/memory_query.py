#!/usr/bin/env python3
"""Query local session memory recall index."""

from __future__ import annotations

import argparse
import importlib.util
import shlex
import sqlite3
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def _load_memory_index_module():
    spec = importlib.util.spec_from_file_location(
        "foxclaw_memory_index_query_support",
        SCRIPT_DIR / "memory_index.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load scripts/memory_index.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


memory_index_lib = _load_memory_index_module()

DB_PATH = memory_index_lib.DB_PATH


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def _query_fts(connection: sqlite3.Connection, text: str, limit: int) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT
            c.id,
            c.timestamp_utc,
            c.focus,
            c.next_actions,
            c.commit_sha,
            bm25(checkpoints_fts) AS rank
        FROM checkpoints_fts
        JOIN checkpoints AS c ON c.id = checkpoints_fts.rowid
        WHERE checkpoints_fts MATCH ?
        ORDER BY rank, c.id DESC
        LIMIT ?
        """,
        (text, limit),
    ).fetchall()


def _like_pattern(text: str) -> str:
    literal = text.strip().strip('"').strip()
    escaped = literal.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _query_like(connection: sqlite3.Connection, text: str, limit: int) -> list[sqlite3.Row]:
    pattern = _like_pattern(text)
    return connection.execute(
        """
        SELECT
            id,
            timestamp_utc,
            focus,
            next_actions,
            commit_sha,
            0.0 AS rank
        FROM checkpoints
        WHERE focus LIKE ? ESCAPE '\\'
            OR next_actions LIKE ? ESCAPE '\\'
            OR commit_sha LIKE ? ESCAPE '\\'
            OR branch LIKE ? ESCAPE '\\'
            OR risks LIKE ? ESCAPE '\\'
            OR decisions LIKE ? ESCAPE '\\'
        ORDER BY id DESC
        LIMIT ?
        """,
        (pattern, pattern, pattern, pattern, pattern, pattern, limit),
    ).fetchall()


def _repair(index_path: Path, source_path: Path) -> None:
    memory_index_lib.build_index(index_path, source_path)
    print(f"[memory-query] repaired index: {memory_index_lib.display_path(index_path)}")


def _remediation_command(index_path: Path, source_path: Path) -> str:
    command = ["python", "scripts/memory_index.py", "build"]
    if index_path != memory_index_lib.DB_PATH:
        command.extend(["--index-path", str(index_path)])
    if source_path != memory_index_lib.SOURCE_JSONL:
        command.extend(["--source-path", str(source_path)])
    return " ".join(shlex.quote(part) for part in command)


def _print_hits(query: str, rows: list[sqlite3.Row]) -> int:
    if not rows:
        print(f"[memory-query] no hits for: {query}")
        return 0

    print(f"[memory-query] top {len(rows)} hits for: {query}")
    for idx, row in enumerate(rows, start=1):
        print(f"{idx}. {row['timestamp_utc']}  commit={row['commit_sha']}")
        print(f"   focus: {row['focus']}")
        print(f"   next:  {row['next_actions']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", help="FTS5 query text")
    parser.add_argument("--limit", type=int, default=5, help="max rows to return")
    parser.add_argument("--index-path", type=Path, default=None, help="path to the SQLite index")
    parser.add_argument("--source-path", type=Path, default=None, help="path to SESSION_MEMORY.jsonl")
    parser.add_argument(
        "--repair",
        action="store_true",
        help="rebuild the index automatically when the schema is missing or stale",
    )
    args = parser.parse_args()

    index_path = memory_index_lib.resolve_index_path(args.index_path)
    source_path = memory_index_lib.resolve_source_path(args.source_path, args.index_path)
    remediation = _remediation_command(index_path, source_path)
    inspection = memory_index_lib.inspect_index(index_path)

    needs_repair = (
        not inspection.exists
        or not inspection.can_query
        or (args.repair and inspection.fts_capable and not inspection.has_fts)
    )
    if needs_repair:
        if args.repair:
            try:
                _repair(index_path, source_path)
            except (OSError, sqlite3.Error) as exc:
                print(f"[memory-query] operational error: {exc}")
                print(f"[memory-query] run: {remediation}")
                return 1
            inspection = memory_index_lib.inspect_index(index_path)
        else:
            reason = inspection.error or "missing index schema"
            print(f"[memory-query] operational error: {reason}")
            print(f"[memory-query] run: {remediation}")
            return 1

    if not inspection.can_query:
        reason = inspection.error or "missing checkpoints table"
        print(f"[memory-query] operational error: {reason}")
        print(f"[memory-query] run: {remediation}")
        return 1

    try:
        with _connect(index_path) as connection:
            if inspection.has_fts:
                rows = _query_fts(connection, args.query, args.limit)
            else:
                print(
                    "[memory-query] warning: checkpoints_fts unavailable; "
                    "using LIKE fallback"
                )
                rows = _query_like(connection, args.query, args.limit)
    except sqlite3.OperationalError as exc:
        message = str(exc)
        if inspection.can_query and "checkpoints_fts" in message:
            print(
                "[memory-query] warning: checkpoints_fts unavailable; "
                "using LIKE fallback"
            )
            with _connect(index_path) as connection:
                rows = _query_like(connection, args.query, args.limit)
        else:
            print(f"[memory-query] operational error: {message}")
            print(f"[memory-query] run: {remediation}")
            return 1
    except sqlite3.Error as exc:
        print(f"[memory-query] operational error: {exc}")
        print(f"[memory-query] run: {remediation}")
        return 1

    return _print_hits(args.query, rows)


if __name__ == "__main__":
    raise SystemExit(main())
