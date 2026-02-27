#!/usr/bin/env python3
"""Query local session memory recall index."""

from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MEMORY_DIR_ENV = "FOXCLAW_SESSION_MEMORY_DIR"
DB_PATH = (
    Path(os.environ[MEMORY_DIR_ENV]).expanduser()
    if MEMORY_DIR_ENV in os.environ and os.environ[MEMORY_DIR_ENV].strip()
    else ROOT / "artifacts" / "session_memory"
)
if not DB_PATH.is_absolute():
    DB_PATH = ROOT / DB_PATH
DB_PATH = DB_PATH / "index.sqlite"


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def _query(path: Path, text: str, limit: int) -> list[sqlite3.Row]:
    with _connect(path) as connection:
        return connection.execute(
            """
            SELECT
                c.timestamp_utc,
                c.focus,
                c.next_actions,
                c.commit_sha,
                bm25(checkpoints_fts) AS rank
            FROM checkpoints_fts
            JOIN checkpoints AS c ON c.id = checkpoints_fts.rowid
            WHERE checkpoints_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (text, limit),
        ).fetchall()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", help="FTS5 query text")
    parser.add_argument("--limit", type=int, default=5, help="max rows to return")
    args = parser.parse_args()

    if not DB_PATH.exists():
        print(
            "[memory-query] missing artifacts/session_memory/index.sqlite; "
            "run: python scripts/memory_index.py build"
        )
        return 1

    rows = _query(DB_PATH, args.query, args.limit)
    if not rows:
        print(f"[memory-query] no hits for: {args.query}")
        return 0

    print(f"[memory-query] top {len(rows)} hits for: {args.query}")
    for idx, row in enumerate(rows, start=1):
        print(f"{idx}. {row['timestamp_utc']}  commit={row['commit_sha']}")
        print(f"   focus: {row['focus']}")
        print(f"   next:  {row['next_actions']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
