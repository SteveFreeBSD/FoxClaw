"""Offline extension reputation correlation from local intel snapshots."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from foxclaw.intel.sqlite import table_exists
from foxclaw.models import ExtensionEvidence


@dataclass(frozen=True, slots=True)
class _AmoIntelRecord:
    source_name: str
    addon_id: str
    version: str | None
    listed: bool
    reputation: Literal["low", "medium", "high"]
    review_count: int | None
    average_daily_users: int | None
    recommended: bool | None
    reason: str | None
    reference_url: str | None


def apply_extension_reputation_from_snapshot(
    *,
    extensions: ExtensionEvidence,
    store_dir: Path,
    snapshot_id: str,
) -> None:
    """Annotate extension entries with AMO reputation intel from a pinned snapshot."""
    records_by_addon = _load_amo_extension_intel(store_dir=store_dir, snapshot_id=snapshot_id)
    for entry in extensions.entries:
        if entry.source_kind in {"builtin", "system"}:
            continue
        record = _resolve_best_record(
            addon_id=entry.addon_id,
            version=entry.version,
            records_by_addon=records_by_addon,
        )
        if record is None:
            continue
        entry.intel_source = record.source_name
        entry.intel_reference_url = record.reference_url
        entry.intel_version = record.version
        entry.intel_reputation_level = record.reputation
        entry.intel_listed = record.listed
        entry.intel_review_count = record.review_count
        entry.intel_average_daily_users = record.average_daily_users
        entry.intel_recommended = record.recommended
        entry.intel_reason = record.reason


def _load_amo_extension_intel(
    *, store_dir: Path, snapshot_id: str
) -> dict[str, list[_AmoIntelRecord]]:
    db_path = store_dir / "intel.db"
    if not db_path.is_file():
        return {}

    try:
        with sqlite3.connect(db_path) as connection:
            if not table_exists(connection, table_name="amo_extension_intel"):
                return {}
            rows = connection.execute(
                """
                SELECT
                    source_name,
                    addon_id,
                    version,
                    listed,
                    reputation,
                    review_count,
                    average_daily_users,
                    recommended,
                    reason,
                    reference_url
                FROM amo_extension_intel
                WHERE snapshot_id = ?
                ORDER BY addon_id, version, source_name, reputation, listed, reference_url, reason;
                """,
                (snapshot_id,),
            ).fetchall()
    except sqlite3.Error as exc:
        raise ValueError(f"intel extension reputation query failed: {db_path}: {exc}") from exc

    records_by_addon: dict[str, list[_AmoIntelRecord]] = {}
    for (
        source_name,
        addon_id,
        version,
        listed,
        reputation,
        review_count,
        average_daily_users,
        recommended,
        reason,
        reference_url,
    ) in rows:
        normalized_addon_id = str(addon_id).strip().lower()
        if not normalized_addon_id:
            continue
        records_by_addon.setdefault(normalized_addon_id, []).append(
            _AmoIntelRecord(
                source_name=str(source_name),
                addon_id=normalized_addon_id,
                version=_normalize_version(version),
                listed=bool(int(listed)),
                reputation=_normalize_reputation(reputation),
                review_count=int(review_count) if review_count is not None else None,
                average_daily_users=(
                    int(average_daily_users) if average_daily_users is not None else None
                ),
                recommended=(bool(int(recommended)) if recommended is not None else None),
                reason=str(reason) if reason is not None else None,
                reference_url=str(reference_url) if reference_url is not None else None,
            )
        )
    return records_by_addon


def _normalize_reputation(value: object) -> Literal["low", "medium", "high"]:
    normalized = str(value).strip().lower()
    if normalized in {"low", "medium", "high"}:
        return cast(Literal["low", "medium", "high"], normalized)
    return "low"


def _normalize_version(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _resolve_best_record(
    *,
    addon_id: str,
    version: str | None,
    records_by_addon: dict[str, list[_AmoIntelRecord]],
) -> _AmoIntelRecord | None:
    key = addon_id.strip().lower()
    if not key:
        return None
    candidates = records_by_addon.get(key)
    if not candidates:
        return None

    normalized_version = _normalize_version(version)
    if normalized_version is not None:
        exact = [item for item in candidates if item.version == normalized_version]
        if exact:
            return sorted(
                exact,
                key=lambda item: (
                    item.source_name,
                    item.reputation,
                    int(item.listed),
                    item.reference_url or "",
                    item.reason or "",
                ),
            )[0]

    no_version = [item for item in candidates if item.version is None]
    if no_version:
        return sorted(
            no_version,
            key=lambda item: (
                item.source_name,
                item.reputation,
                int(item.listed),
                item.reference_url or "",
                item.reason or "",
            ),
        )[0]
    return candidates[0]
