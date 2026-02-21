"""Local persistence for intelligence synchronization snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from foxclaw.intel.models import IntelSnapshotManifest, IntelSourceIndex, IntelSourceMaterial


def default_store_dir() -> Path:
    """Return the default local intelligence store directory."""
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home).expanduser() / "foxclaw" / "intel"
    return Path.home() / ".local" / "share" / "foxclaw" / "intel"


def build_snapshot_id(sources: list[IntelSourceMaterial]) -> str:
    """Build deterministic snapshot id from sorted source hashes."""
    digest = hashlib.sha256()
    for source in sorted(sources, key=lambda item: item.name):
        digest.update(source.name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(source.sha256.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def write_snapshot(
    *,
    store_dir: Path,
    source_payloads: list[tuple[IntelSourceMaterial, bytes]],
    source_indexes: dict[str, IntelSourceIndex] | None = None,
) -> tuple[IntelSnapshotManifest, Path]:
    """Persist source payloads and manifest into the local store."""
    store_dir.mkdir(parents=True, exist_ok=True)

    metadata_only = [item for item, _ in source_payloads]
    snapshot_id = build_snapshot_id(metadata_only)
    snapshot_dir = store_dir / "snapshots" / snapshot_id
    sources_dir = snapshot_dir / "sources"
    sources_dir.mkdir(parents=True, exist_ok=True)

    normalized_indexes = source_indexes or {}
    manifest_sources: list[IntelSourceMaterial] = []
    for source, payload in sorted(source_payloads, key=lambda item: item[0].name):
        artifact_name = f"{quote(source.name, safe='')}.blob"
        artifact_path = sources_dir / artifact_name
        artifact_path.write_bytes(payload)

        source_index = normalized_indexes.get(source.name)
        source_entry = source.model_copy(
            update={
                "artifact_path": str(artifact_path),
                "schema_version": (
                    source_index.schema_version if source_index is not None else source.schema_version
                ),
                "adapter": source_index.adapter if source_index is not None else source.adapter,
                "records_indexed": (
                    source_index.record_count if source_index is not None else source.records_indexed
                ),
            }
        )
        manifest_sources.append(source_entry)

    manifest = IntelSnapshotManifest(
        snapshot_id=snapshot_id,
        generated_at=datetime.now(UTC),
        source_count=len(manifest_sources),
        sources=manifest_sources,
    )

    manifest_path = snapshot_dir / "manifest.json"
    manifest_payload = manifest.model_dump(mode="json")
    manifest_text = json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n"
    manifest_path.write_text(manifest_text, encoding="utf-8")
    manifest_sha256 = hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()

    _write_latest_pointer(store_dir=store_dir, manifest=manifest, manifest_path=manifest_path)
    _upsert_sqlite_index(
        store_dir=store_dir,
        manifest=manifest,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        source_indexes=normalized_indexes,
    )
    return manifest, manifest_path


def _write_latest_pointer(
    *, store_dir: Path, manifest: IntelSnapshotManifest, manifest_path: Path
) -> None:
    pointer_path = store_dir / "latest.json"
    payload = {
        "schema_version": "1.0.0",
        "snapshot_id": manifest.snapshot_id,
        "generated_at": manifest.generated_at.isoformat(),
        "manifest_path": str(manifest_path),
    }
    pointer_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _upsert_sqlite_index(
    *,
    store_dir: Path,
    manifest: IntelSnapshotManifest,
    manifest_path: Path,
    manifest_sha256: str,
    source_indexes: dict[str, IntelSourceIndex],
) -> None:
    db_path = store_dir / "intel.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS intel_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                generated_at TEXT NOT NULL,
                source_count INTEGER NOT NULL,
                manifest_path TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL
            );
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS source_materials (
                snapshot_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                origin TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                fetched_at TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, source_name),
                FOREIGN KEY (snapshot_id) REFERENCES intel_snapshots(snapshot_id) ON DELETE CASCADE
            );
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS source_indexes (
                snapshot_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                adapter TEXT,
                schema_version TEXT,
                record_count INTEGER NOT NULL,
                PRIMARY KEY (snapshot_id, source_name),
                FOREIGN KEY (snapshot_id, source_name)
                    REFERENCES source_materials(snapshot_id, source_name) ON DELETE CASCADE
            );
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mozilla_advisories (
                snapshot_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                advisory_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                affected_versions TEXT NOT NULL,
                fixed_version TEXT,
                severity TEXT,
                summary TEXT,
                reference_url TEXT,
                PRIMARY KEY (snapshot_id, source_name, advisory_id, cve_id, affected_versions),
                FOREIGN KEY (snapshot_id, source_name)
                    REFERENCES source_materials(snapshot_id, source_name) ON DELETE CASCADE
            );
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS extension_blocklist (
                snapshot_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                addon_id TEXT NOT NULL,
                version TEXT,
                block_state TEXT NOT NULL,
                reason TEXT,
                reference_url TEXT,
                PRIMARY KEY (snapshot_id, source_name, addon_id, version, block_state),
                FOREIGN KEY (snapshot_id, source_name)
                    REFERENCES source_materials(snapshot_id, source_name) ON DELETE CASCADE
            );
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS nvd_cves (
                snapshot_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                severity TEXT,
                summary TEXT,
                reference_url TEXT,
                PRIMARY KEY (snapshot_id, source_name, cve_id, severity, reference_url),
                FOREIGN KEY (snapshot_id, source_name)
                    REFERENCES source_materials(snapshot_id, source_name) ON DELETE CASCADE
            );
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_list_records (
                snapshot_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                severity TEXT,
                summary TEXT,
                reference_url TEXT,
                PRIMARY KEY (snapshot_id, source_name, cve_id, severity, reference_url),
                FOREIGN KEY (snapshot_id, source_name)
                    REFERENCES source_materials(snapshot_id, source_name) ON DELETE CASCADE
            );
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS kev_catalog (
                snapshot_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                vendor_project TEXT,
                product TEXT,
                date_added TEXT,
                due_date TEXT,
                known_ransomware_campaign_use TEXT,
                short_description TEXT,
                reference_url TEXT,
                PRIMARY KEY (
                    snapshot_id,
                    source_name,
                    cve_id,
                    vendor_project,
                    product,
                    date_added,
                    due_date,
                    known_ransomware_campaign_use,
                    reference_url
                ),
                FOREIGN KEY (snapshot_id, source_name)
                    REFERENCES source_materials(snapshot_id, source_name) ON DELETE CASCADE
            );
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS epss_scores (
                snapshot_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                score REAL NOT NULL,
                percentile REAL,
                reference_url TEXT,
                PRIMARY KEY (snapshot_id, source_name, cve_id, score, percentile, reference_url),
                FOREIGN KEY (snapshot_id, source_name)
                    REFERENCES source_materials(snapshot_id, source_name) ON DELETE CASCADE
            );
            """
        )

        connection.execute(
            """
            INSERT OR REPLACE INTO intel_snapshots (
                snapshot_id, generated_at, source_count, manifest_path, manifest_sha256
            ) VALUES (?, ?, ?, ?, ?);
            """,
            (
                manifest.snapshot_id,
                manifest.generated_at.isoformat(),
                manifest.source_count,
                str(manifest_path),
                manifest_sha256,
            ),
        )

        for source in manifest.sources:
            connection.execute(
                """
                INSERT OR REPLACE INTO source_materials (
                    snapshot_id, source_name, origin, content_sha256, size_bytes, fetched_at, artifact_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    manifest.snapshot_id,
                    source.name,
                    source.origin,
                    source.sha256,
                    source.size_bytes,
                    source.fetched_at.isoformat(),
                    source.artifact_path,
                ),
            )
            connection.execute(
                """
                INSERT OR REPLACE INTO source_indexes (
                    snapshot_id, source_name, adapter, schema_version, record_count
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (
                    manifest.snapshot_id,
                    source.name,
                    source.adapter,
                    source.schema_version,
                    source.records_indexed,
                ),
            )

            source_index = source_indexes.get(source.name)
            if source_index is None:
                continue

            for advisory in source_index.mozilla_advisories:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO mozilla_advisories (
                        snapshot_id,
                        source_name,
                        advisory_id,
                        cve_id,
                        affected_versions,
                        fixed_version,
                        severity,
                        summary,
                        reference_url
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        manifest.snapshot_id,
                        source.name,
                        advisory.advisory_id,
                        advisory.cve_id,
                        advisory.affected_versions,
                        advisory.fixed_version,
                        advisory.severity,
                        advisory.summary,
                        advisory.reference_url,
                    ),
                )
            for entry in source_index.extension_blocklist:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO extension_blocklist (
                        snapshot_id,
                        source_name,
                        addon_id,
                        version,
                        block_state,
                        reason,
                        reference_url
                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        manifest.snapshot_id,
                        source.name,
                        entry.addon_id,
                        entry.version,
                        entry.block_state,
                        entry.reason,
                        entry.reference_url,
                    ),
                )
            for nvd_cve in source_index.nvd_cves:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO nvd_cves (
                        snapshot_id,
                        source_name,
                        cve_id,
                        severity,
                        summary,
                        reference_url
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        manifest.snapshot_id,
                        source.name,
                        nvd_cve.cve_id,
                        nvd_cve.severity,
                        nvd_cve.summary,
                        nvd_cve.reference_url,
                    ),
                )
            for cve_list_record in source_index.cve_list_records:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO cve_list_records (
                        snapshot_id,
                        source_name,
                        cve_id,
                        severity,
                        summary,
                        reference_url
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        manifest.snapshot_id,
                        source.name,
                        cve_list_record.cve_id,
                        cve_list_record.severity,
                        cve_list_record.summary,
                        cve_list_record.reference_url,
                    ),
                )
            for kev in source_index.kev_records:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO kev_catalog (
                        snapshot_id,
                        source_name,
                        cve_id,
                        vendor_project,
                        product,
                        date_added,
                        due_date,
                        known_ransomware_campaign_use,
                        short_description,
                        reference_url
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        manifest.snapshot_id,
                        source.name,
                        kev.cve_id,
                        kev.vendor_project,
                        kev.product,
                        kev.date_added,
                        kev.due_date,
                        kev.known_ransomware_campaign_use,
                        kev.short_description,
                        kev.reference_url,
                    ),
                )
            for epss in source_index.epss_records:
                connection.execute(
                    """
                    INSERT OR REPLACE INTO epss_scores (
                        snapshot_id,
                        source_name,
                        cve_id,
                        score,
                        percentile,
                        reference_url
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        manifest.snapshot_id,
                        source.name,
                        epss.cve_id,
                        epss.score,
                        epss.percentile,
                        epss.reference_url,
                    ),
                )

        connection.commit()
