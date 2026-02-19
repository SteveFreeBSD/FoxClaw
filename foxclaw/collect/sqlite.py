"""Read-only SQLite health checks for Firefox profile databases."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import quote

from foxclaw.models import SqliteCheck, SqliteEvidence

DEFAULT_SQLITE_DBS: tuple[str, ...] = ("places.sqlite", "cookies.sqlite")


def collect_sqlite_quick_checks(profile_dir: Path) -> SqliteEvidence:
    """Run `PRAGMA quick_check` in read-only mode for core Firefox SQLite DBs."""
    checks: list[SqliteCheck] = []
    for db_name in DEFAULT_SQLITE_DBS:
        db_path = profile_dir / db_name
        checks.append(_run_quick_check(db_path))
    return SqliteEvidence(checks=checks)


def _run_quick_check(db_path: Path) -> SqliteCheck:
    if not db_path.is_file():
        return SqliteCheck(
            db_path=str(db_path),
            opened_ro=False,
            quick_check_result="error: file not found",
        )

    uri = _sqlite_ro_uri(db_path)
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return SqliteCheck(
            db_path=str(db_path),
            opened_ro=False,
            quick_check_result=f"error: {exc}",
        )

    try:
        rows = connection.execute("PRAGMA quick_check;").fetchall()
    except sqlite3.Error as exc:
        result = f"error: {exc}"
    else:
        if not rows:
            result = "error: no result from quick_check"
        else:
            row_values = [str(row[0]) for row in rows if row]
            result = "ok" if row_values == ["ok"] else "; ".join(row_values)
    finally:
        connection.close()

    return SqliteCheck(db_path=str(db_path), opened_ro=True, quick_check_result=result)


def _sqlite_ro_uri(db_path: Path) -> str:
    quoted = quote(str(db_path), safe="/")
    return f"file:{quoted}?mode=ro"
