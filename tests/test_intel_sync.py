from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from foxclaw.cli import app
from foxclaw.intel.sync import sync_sources
from typer.testing import CliRunner

INTEL_FIXTURE = Path("tests/fixtures/intel/mozilla_firefox_advisories.v1.json")


def test_sync_sources_writes_manifest_and_sqlite_index(tmp_path: Path) -> None:
    source_a = tmp_path / "mozilla.json"
    source_a.write_text('{"z":1,"a":2}\n', encoding="utf-8")
    source_b = tmp_path / "blocklist.txt"
    source_b.write_text("blocked-addon@example.com\n", encoding="utf-8")

    store_dir = tmp_path / "intel-store"
    result = sync_sources(
        source_specs=[
            f"mozilla={source_a}",
            f"blocklist={source_b}",
        ],
        store_dir=store_dir,
        normalize_json=True,
        cwd=tmp_path,
    )

    assert result.manifest.source_count == 2
    assert result.manifest_path.is_file()
    assert (store_dir / "latest.json").is_file()

    snapshot_dir = store_dir / "snapshots" / result.manifest.snapshot_id / "sources"
    mozilla_source = next(item for item in result.manifest.sources if item.name == "mozilla")
    mozilla_artifact = Path(mozilla_source.artifact_path)
    assert mozilla_artifact.is_file()
    assert mozilla_artifact.read_text(encoding="utf-8") == '{"a":2,"z":1}\n'
    assert mozilla_artifact.parent == snapshot_dir

    with sqlite3.connect(store_dir / "intel.db") as connection:
        snapshot_rows = connection.execute("SELECT COUNT(*) FROM intel_snapshots").fetchone()
        source_rows = connection.execute("SELECT COUNT(*) FROM source_materials").fetchone()
        assert snapshot_rows == (1,)
        assert source_rows == (2,)


def test_sync_sources_reuses_snapshot_id_for_identical_inputs(tmp_path: Path) -> None:
    source_file = tmp_path / "source.json"
    source_file.write_text('{"b":1,"a":2}\n', encoding="utf-8")

    store_dir = tmp_path / "intel-store"
    first = sync_sources(
        source_specs=[f"mozilla={source_file}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=tmp_path,
    )
    second = sync_sources(
        source_specs=[f"mozilla={source_file}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=tmp_path,
    )

    assert first.manifest.snapshot_id == second.manifest.snapshot_id


def test_sync_sources_indexes_mozilla_advisories_schema(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    result = sync_sources(
        source_specs=[f"mozilla={INTEL_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    source = result.manifest.sources[0]
    assert source.schema_version == "foxclaw.mozilla.firefox_advisories.v1"
    assert source.adapter == "mozilla_firefox_advisories_v1"
    assert source.records_indexed == 2

    with sqlite3.connect(store_dir / "intel.db") as connection:
        index_rows = connection.execute("SELECT COUNT(*) FROM source_indexes").fetchone()
        advisory_rows = connection.execute("SELECT COUNT(*) FROM mozilla_advisories").fetchone()
        assert index_rows == (1,)
        assert advisory_rows == (2,)


def test_intel_sync_cli_json_output(tmp_path: Path) -> None:
    source_file = tmp_path / "source.json"
    source_file.write_text('{"key":"value"}\n', encoding="utf-8")
    output_file = tmp_path / "manifest.json"
    store_dir = tmp_path / "intel-store"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "intel",
            "sync",
            "--source",
            f"mozilla={source_file}",
            "--store-dir",
            str(store_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["source_count"] == 1
    assert payload["sources"][0]["name"] == "mozilla"

    copy_result = runner.invoke(
        app,
        [
            "intel",
            "sync",
            "--source",
            f"mozilla={source_file}",
            "--store-dir",
            str(store_dir),
            "--output",
            str(output_file),
        ],
    )
    assert copy_result.exit_code == 0
    assert output_file.is_file()


def test_intel_sync_cli_rejects_duplicate_source_names(tmp_path: Path) -> None:
    source_a = tmp_path / "a.json"
    source_b = tmp_path / "b.json"
    source_a.write_text("{}", encoding="utf-8")
    source_b.write_text("{}", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "intel",
            "sync",
            "--source",
            f"dup={source_a}",
            "--source",
            f"dup={source_b}",
            "--store-dir",
            str(tmp_path / "intel-store"),
        ],
    )
    assert result.exit_code == 1
    assert "duplicate source name 'dup'" in result.stdout
