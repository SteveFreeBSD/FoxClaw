"""Offline extension blocklist correlation from local intel snapshots."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from foxclaw.intel.sqlite import table_exists
from foxclaw.models import ExtensionEvidence


def apply_extension_blocklist_from_snapshot(
    *,
    extensions: ExtensionEvidence,
    store_dir: Path,
    snapshot_id: str,
) -> None:
    """Annotate extension entries with blocklist status from a pinned snapshot."""
    rules = _load_blocklist_rules(store_dir=store_dir, snapshot_id=snapshot_id)
    for entry in extensions.entries:
        if entry.source_kind in {"builtin", "system"}:
            entry.blocklisted = False
            continue
        entry.blocklisted = _matches_blocklist(
            addon_id=entry.addon_id,
            version=entry.version,
            rules=rules,
        )


def _load_blocklist_rules(*, store_dir: Path, snapshot_id: str) -> dict[str, set[str | None]]:
    db_path = store_dir / "intel.db"
    if not db_path.is_file():
        return {}

    try:
        with sqlite3.connect(db_path) as connection:
            if not table_exists(connection, table_name="extension_blocklist"):
                return {}
            rows = connection.execute(
                """
                SELECT addon_id, version
                FROM extension_blocklist
                WHERE snapshot_id = ?
                ORDER BY addon_id, version;
                """,
                (snapshot_id,),
            ).fetchall()
    except sqlite3.Error as exc:
        raise ValueError(f"intel extension blocklist query failed: {db_path}: {exc}") from exc

    rules: dict[str, set[str | None]] = {}
    for addon_id, version in rows:
        normalized_addon_id = str(addon_id).strip().lower()
        if not normalized_addon_id:
            continue
        normalized_version = _normalize_version(version)
        rules.setdefault(normalized_addon_id, set()).add(normalized_version)
    return rules


def _normalize_version(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _matches_blocklist(
    *, addon_id: str, version: str | None, rules: dict[str, set[str | None]]
) -> bool:
    key = addon_id.strip().lower()
    if not key:
        return False
    versions = rules.get(key)
    if not versions:
        return False
    if None in versions:
        return True
    return _normalize_version(version) in versions
