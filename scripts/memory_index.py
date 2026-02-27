#!/usr/bin/env python3
"""Build/query support index for session memory checkpoints."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MEMORY_DIR_ENV = "FOXCLAW_SESSION_MEMORY_DIR"
INDEX_FILENAME = "index.sqlite"
SOURCE_FILENAME = "SESSION_MEMORY.jsonl"
SCHEMA_VERSION = "2"
MEMORY_DIR = (
    Path(os.environ[MEMORY_DIR_ENV]).expanduser()
    if MEMORY_DIR_ENV in os.environ and os.environ[MEMORY_DIR_ENV].strip()
    else ROOT / "artifacts" / "session_memory"
)
if not MEMORY_DIR.is_absolute():
    MEMORY_DIR = ROOT / MEMORY_DIR
SOURCE_JSONL = MEMORY_DIR / SOURCE_FILENAME
DB_PATH = MEMORY_DIR / INDEX_FILENAME


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


@dataclass(frozen=True)
class IndexInspection:
    path: Path
    exists: bool
    can_query: bool
    has_fts: bool
    fts_capable: bool
    last_checkpoint_id: int | None
    error: str | None = None


@dataclass(frozen=True)
class BuildResult:
    db_path: Path
    source_path: Path
    checkpoints: int
    fts_enabled: bool


def _absolute_path(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        return ROOT / expanded
    return expanded


def resolve_index_path(index_path: Path | None = None) -> Path:
    return _absolute_path(index_path or DB_PATH)


def resolve_source_path(
    source_path: Path | None = None,
    index_path: Path | None = None,
) -> Path:
    if source_path is not None:
        return _absolute_path(source_path)
    if index_path is not None:
        return resolve_index_path(index_path).with_name(SOURCE_FILENAME)
    return _absolute_path(SOURCE_JSONL)


def _read_checkpoints(source_path: Path) -> list[Checkpoint]:
    if not source_path.exists():
        return []

    checkpoints: list[Checkpoint] = []
    for idx, raw_line in enumerate(source_path.read_text(encoding="utf-8").splitlines(), start=1):
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


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def supports_fts5(connection: sqlite3.Connection) -> bool:
    try:
        connection.execute("CREATE VIRTUAL TABLE temp.checkpoints_fts_probe USING fts5(content)")
        connection.execute("DROP TABLE temp.checkpoints_fts_probe")
        return True
    except sqlite3.OperationalError:
        return False


def _create_schema(connection: sqlite3.Connection, *, fts_enabled: bool) -> None:
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

        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    if fts_enabled:
        connection.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS checkpoints_fts USING fts5(
                focus,
                next_actions,
                commit_sha,
                branch,
                risks,
                decisions
            )
            """
        )


def _write_metadata(
    connection: sqlite3.Connection,
    *,
    source_path: Path,
    fts_enabled: bool,
) -> None:
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "source_path": display_path(source_path),
        "source_exists": "1" if source_path.exists() else "0",
        "fts_enabled": "1" if fts_enabled else "0",
    }
    if source_path.exists():
        stat = source_path.stat()
        metadata["source_size"] = str(stat.st_size)
        metadata["source_mtime_ns"] = str(stat.st_mtime_ns)
    else:
        metadata["source_size"] = "0"
        metadata["source_mtime_ns"] = "0"
    for key, value in metadata.items():
        connection.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def _load_metadata(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        rows = connection.execute("SELECT key, value FROM meta").fetchall()
    except sqlite3.OperationalError:
        return {}
    return {str(row["key"]): str(row["value"]) for row in rows}


def _is_source_unchanged(connection: sqlite3.Connection, source_path: Path) -> bool:
    stored = _load_metadata(connection)
    if not source_path.exists():
        return stored.get("source_exists") == "0"
    current = source_path.stat()
    return (
        stored.get("source_exists") == "1"
        and stored.get("source_size") == str(current.st_size)
        and stored.get("source_mtime_ns") == str(current.st_mtime_ns)
    )


def _existing_tables(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {str(row[0]) for row in rows}


def inspect_index(path: Path) -> IndexInspection:
    resolved = resolve_index_path(path)
    if not resolved.exists():
        return IndexInspection(
            path=resolved,
            exists=False,
            can_query=False,
            has_fts=False,
            fts_capable=False,
            last_checkpoint_id=None,
            error="missing index",
        )

    try:
        with _connect(resolved) as connection:
            tables = _existing_tables(connection)
            can_query = "checkpoints" in tables
            has_fts = "checkpoints_fts" in tables
            last_checkpoint_id = None
            if can_query:
                row = connection.execute("SELECT MAX(id) AS last_id FROM checkpoints").fetchone()
                last_checkpoint_id = None if row is None else row["last_id"]
            return IndexInspection(
                path=resolved,
                exists=True,
                can_query=can_query,
                has_fts=has_fts,
                fts_capable=supports_fts5(connection),
                last_checkpoint_id=last_checkpoint_id,
            )
    except sqlite3.Error as exc:
        return IndexInspection(
            path=resolved,
            exists=True,
            can_query=False,
            has_fts=False,
            fts_capable=False,
            last_checkpoint_id=None,
            error=str(exc),
        )


def _populate(
    connection: sqlite3.Connection,
    checkpoints: list[Checkpoint],
    *,
    fts_enabled: bool,
) -> None:
    if fts_enabled:
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
        if fts_enabled:
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


def _remove_existing_index_files(db_path: Path) -> None:
    for candidate in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
        if candidate.exists():
            candidate.unlink()


def build_index(db_path: Path, source_path: Path) -> BuildResult:
    checkpoints = _read_checkpoints(source_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _remove_existing_index_files(db_path)

    with _connect(db_path) as connection:
        fts_enabled = supports_fts5(connection)
        _create_schema(connection, fts_enabled=fts_enabled)
        _populate(connection, checkpoints, fts_enabled=fts_enabled)
        _write_metadata(connection, source_path=source_path, fts_enabled=fts_enabled)
        connection.commit()

    return BuildResult(
        db_path=db_path,
        source_path=source_path,
        checkpoints=len(checkpoints),
        fts_enabled=fts_enabled,
    )


def cmd_build(_args: argparse.Namespace) -> int:
    db_path = resolve_index_path(_args.index_path)
    source_path = resolve_source_path(_args.source_path, _args.index_path)
    result = build_index(db_path, source_path)
    if not result.fts_enabled:
        print("[memory-index] warning: SQLite FTS5 unavailable; queries will use LIKE fallback")
    print(
        f"[memory-index] built {display_path(result.db_path)} "
        f"from {display_path(result.source_path)} ({result.checkpoints} checkpoints)"
    )
    return 0


def cmd_update(_args: argparse.Namespace) -> int:
    db_path = resolve_index_path(_args.index_path)
    source_path = resolve_source_path(_args.source_path, _args.index_path)
    inspection = inspect_index(db_path)
    if not inspection.exists:
        return cmd_build(_args)

    if not inspection.can_query or (inspection.fts_capable and not inspection.has_fts):
        print(f"[memory-index] stale schema detected at {display_path(db_path)}; rebuilding")
        return cmd_build(_args)

    with _connect(db_path) as connection:
        _create_schema(connection, fts_enabled=inspection.fts_capable)
        if _is_source_unchanged(connection, source_path):
            count = connection.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
            print(
                f"[memory-index] up to date: {display_path(db_path)} "
                f"({count} checkpoints)"
            )
            return 0

    return cmd_build(_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="rebuild index from the local session memory journal")
    build.add_argument("--index-path", type=Path, default=None, help="path to the SQLite index")
    build.add_argument("--source-path", type=Path, default=None, help="path to SESSION_MEMORY.jsonl")
    build.set_defaults(func=cmd_build)

    update = sub.add_parser("update", help="refresh index when source log changed")
    update.add_argument("--index-path", type=Path, default=None, help="path to the SQLite index")
    update.add_argument("--source-path", type=Path, default=None, help="path to SESSION_MEMORY.jsonl")
    update.set_defaults(func=cmd_update)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
