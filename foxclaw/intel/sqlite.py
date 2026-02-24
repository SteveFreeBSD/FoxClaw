"""Shared SQLite database helpers for intel correlation modules."""

from __future__ import annotations

import sqlite3


def table_exists(connection: sqlite3.Connection, *, table_name: str) -> bool:
    """Return True if the given SQLite table exists in the database.

    Args:
        connection: An active SQLite database connection.
        table_name: The name of the table to check for existence.
    """
    cursor = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (table_name,),
    )
    return cursor.fetchone() is not None
