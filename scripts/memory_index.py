#!/usr/bin/env python3
"""Build/query support index for session memory checkpoints."""

from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOURCE_JSONL = ROOT / "docs" / "SESSION_MEMORY.jsonl"
DB_PATH = ROOT / "artifacts" / "memory" / "index.sqlite"


@dataclass(frozen=True)
class Checkpoint:
    source_line: int
    timestamp_utc: str
    branch: str
    commit_sha: str
    focus: str
    next_actions: str
    risks: str
    decisions: str


def _read_checkpoints() -> list[Checkpoint]:
    if not SOURCE_JSONL.exists():
        raise FileNotFoundError(f"missing source log: {SOURCE_JSONL}")

    checkpoints: list[Checkpoint] = []
    for idx, raw_line in enumerate(SOURCE_JSONL.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        payload: dict[str, Any] = json.loads(line)
        checkpoints.append(
            Checkpoint(
                source_line=idx,
                timestamp_utc=str(payload.get("timestamp_utc", "")),
                branch=str(payload.get("branch", "")),
                commit_sha=str(payload.get("commit", "")),
                focus=str(payload.get("focus", "")),
                next_actions=str(payload.get("next_actions", "")),
                risks=str(payload.get("risks", "") or ""),
                decisions=str(payload.get("decisions", "") or ""),
            )
        )
    return checkpoints


def _connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS checkpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_line INTEGER NOT NULL UNIQUE,
            timestamp_utc TEXT NOT NULL,
            branch TEXT NOT NULL,
            commit_sha TEXT NOT NULL,
            focus TEXT NOT NULL,
            next_actions TEXT NOT NULL,
            risks TEXT NOT NULL,
            decisions TEXT NOT NULL
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS checkpoints_fts USING fts5(
            focus,
            next_actions,
            commit_sha,
            branch,
            risks,
            decisions
        );

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )


def _write_metadata(connection: sqlite3.Connection) -> None:
    stat = SOURCE_JSONL.stat()
    metadata = {
        "source_path": str(SOURCE_JSONL.relative_to(ROOT)),
        "source_size": str(stat.st_size),
        "source_mtime_ns": str(stat.st_mtime_ns),
    }
    for key, value in metadata.items():
        connection.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def _load_metadata(connection: sqlite3.Connection) -> dict[str, str]:
    rows = connection.execute("SELECT key, value FROM meta").fetchall()
    return {str(row["key"]): str(row["value"]) for row in rows}


def _is_source_unchanged(connection: sqlite3.Connection) -> bool:
    if not SOURCE_JSONL.exists():
        return False
    current = SOURCE_JSONL.stat()
    stored = _load_metadata(connection)
    return (
        stored.get("source_size") == str(current.st_size)
        and stored.get("source_mtime_ns") == str(current.st_mtime_ns)
    )


def _populate(connection: sqlite3.Connection, checkpoints: list[Checkpoint]) -> None:
    connection.execute("DELETE FROM checkpoints_fts")
    connection.execute("DELETE FROM checkpoints")

    for checkpoint in checkpoints:
        cursor = connection.execute(
            """
            INSERT INTO checkpoints (
                source_line,
                timestamp_utc,
                branch,
                commit_sha,
                focus,
                next_actions,
                risks,
                decisions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checkpoint.source_line,
                checkpoint.timestamp_utc,
                checkpoint.branch,
                checkpoint.commit_sha,
                checkpoint.focus,
                checkpoint.next_actions,
                checkpoint.risks,
                checkpoint.decisions,
            ),
        )
        row_id = int(cursor.lastrowid)
        connection.execute(
            """
            INSERT INTO checkpoints_fts (
                rowid,
                focus,
                next_actions,
                commit_sha,
                branch,
                risks,
                decisions
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row_id,
                checkpoint.focus,
                checkpoint.next_actions,
                checkpoint.commit_sha,
                checkpoint.branch,
                checkpoint.risks,
                checkpoint.decisions,
            ),
        )


def cmd_build(_args: argparse.Namespace) -> int:
    checkpoints = _read_checkpoints()
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()

    with _connect(DB_PATH) as connection:
        _create_schema(connection)
        _populate(connection, checkpoints)
        _write_metadata(connection)
        connection.commit()

    print(
        f"[memory-index] built {DB_PATH.relative_to(ROOT)} "
        f"from {SOURCE_JSONL.relative_to(ROOT)} ({len(checkpoints)} checkpoints)"
    )
    return 0


def cmd_update(_args: argparse.Namespace) -> int:
    if not DB_PATH.exists():
        return cmd_build(_args)

    with _connect(DB_PATH) as connection:
        _create_schema(connection)
        if _is_source_unchanged(connection):
            count = connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
            print(
                f"[memory-index] up to date: {DB_PATH.relative_to(ROOT)} "
                f"({count} checkpoints)"
            )
            return 0

    return cmd_build(_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="rebuild index from SESSION_MEMORY.jsonl")
    build.set_defaults(func=cmd_build)

    update = sub.add_parser("update", help="refresh index when source log changed")
    update.set_defaults(func=cmd_update)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
