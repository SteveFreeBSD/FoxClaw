from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from foxclaw.cli import app
from foxclaw.intel.sync import sync_sources
from typer.testing import CliRunner

INTEL_FIXTURE = Path("tests/fixtures/intel/mozilla_firefox_advisories.v1.json")
BLOCKLIST_FIXTURE = Path("tests/fixtures/intel/mozilla_extension_blocklist.v1.json")
NVD_FIXTURE = Path("tests/fixtures/intel/nvd_cve_records.v1.json")
CVE_LIST_FIXTURE = Path("tests/fixtures/intel/cve_list_records.v1.json")
KEV_FIXTURE = Path("tests/fixtures/intel/cisa_kev.v1.json")
EPSS_FIXTURE = Path("tests/fixtures/intel/epss_scores.v1.json")


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


def test_sync_sources_indexes_extension_blocklist_schema(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    result = sync_sources(
        source_specs=[f"blocklist={BLOCKLIST_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    source = result.manifest.sources[0]
    assert source.schema_version == "foxclaw.mozilla.extension_blocklist.v1"
    assert source.adapter == "mozilla_extension_blocklist_v1"
    assert source.records_indexed == 2

    with sqlite3.connect(store_dir / "intel.db") as connection:
        index_rows = connection.execute("SELECT COUNT(*) FROM source_indexes").fetchone()
        blocklist_rows = connection.execute(
            "SELECT COUNT(*) FROM extension_blocklist"
        ).fetchone()
        assert index_rows == (1,)
        assert blocklist_rows == (2,)


def test_sync_sources_indexes_nvd_cve_schema(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    result = sync_sources(
        source_specs=[f"nvd={NVD_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    source = result.manifest.sources[0]
    assert source.schema_version == "foxclaw.nvd.cve_records.v1"
    assert source.adapter == "nvd_cve_records_v1"
    assert source.records_indexed == 2

    with sqlite3.connect(store_dir / "intel.db") as connection:
        index_rows = connection.execute("SELECT COUNT(*) FROM source_indexes").fetchone()
        nvd_rows = connection.execute("SELECT COUNT(*) FROM nvd_cves").fetchone()
        assert index_rows == (1,)
        assert nvd_rows == (2,)


def test_sync_sources_indexes_cve_list_schema(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    result = sync_sources(
        source_specs=[f"cvelist={CVE_LIST_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    source = result.manifest.sources[0]
    assert source.schema_version == "foxclaw.cve.list_records.v1"
    assert source.adapter == "cve_list_records_v1"
    assert source.records_indexed == 2

    with sqlite3.connect(store_dir / "intel.db") as connection:
        index_rows = connection.execute("SELECT COUNT(*) FROM source_indexes").fetchone()
        cve_list_rows = connection.execute("SELECT COUNT(*) FROM cve_list_records").fetchone()
        assert index_rows == (1,)
        assert cve_list_rows == (2,)


def test_sync_sources_indexes_cisa_kev_schema(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    result = sync_sources(
        source_specs=[f"kev={KEV_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    source = result.manifest.sources[0]
    assert source.schema_version == "foxclaw.cisa.known_exploited_vulnerabilities.v1"
    assert source.adapter == "cisa_kev_v1"
    assert source.records_indexed == 1

    with sqlite3.connect(store_dir / "intel.db") as connection:
        index_rows = connection.execute("SELECT COUNT(*) FROM source_indexes").fetchone()
        kev_rows = connection.execute("SELECT COUNT(*) FROM kev_catalog").fetchone()
        assert index_rows == (1,)
        assert kev_rows == (1,)


def test_sync_sources_indexes_epss_scores_schema(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    result = sync_sources(
        source_specs=[f"epss={EPSS_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    source = result.manifest.sources[0]
    assert source.schema_version == "foxclaw.epss.scores.v1"
    assert source.adapter == "epss_scores_v1"
    assert source.records_indexed == 2

    with sqlite3.connect(store_dir / "intel.db") as connection:
        index_rows = connection.execute("SELECT COUNT(*) FROM source_indexes").fetchone()
        epss_rows = connection.execute("SELECT COUNT(*) FROM epss_scores").fetchone()
        assert index_rows == (1,)
        assert epss_rows == (2,)


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


def test_sync_sources_rejects_http_origin_by_default(tmp_path: Path) -> None:
    with pytest.raises(OSError, match="insecure HTTP source blocked by default"):
        sync_sources(
            source_specs=["mozilla=http://intel.invalid/mozilla.json"],
            store_dir=tmp_path / "intel-store",
            normalize_json=True,
            cwd=tmp_path,
        )


def test_sync_sources_allows_http_origin_with_explicit_flag_and_marks_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fake_http_read(origin: str, *, allow_insecure_http: bool) -> bytes:
        assert origin == "http://intel.invalid/mozilla.json"
        assert allow_insecure_http is True
        return b'{"schema_version":"foxclaw.mozilla.firefox_advisories.v1","product":"firefox","advisories":[]}\n'

    monkeypatch.setattr("foxclaw.intel.sync._read_http_payload", _fake_http_read)
    result = sync_sources(
        source_specs=["mozilla=http://intel.invalid/mozilla.json"],
        store_dir=tmp_path / "intel-store",
        normalize_json=True,
        cwd=tmp_path,
        allow_insecure_http=True,
    )

    source = result.manifest.sources[0]
    assert source.transport == "http"
    assert source.insecure_transport is True


def test_intel_sync_cli_rejects_http_origin_by_default(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "intel",
            "sync",
            "--source",
            "mozilla=http://intel.invalid/mozilla.json",
            "--store-dir",
            str(tmp_path / "intel-store"),
        ],
    )
    assert result.exit_code == 1
    assert "insecure HTTP source blocked by default" in result.stdout


def test_intel_sync_cli_allows_http_origin_with_explicit_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fake_http_read(origin: str, *, allow_insecure_http: bool) -> bytes:
        assert origin == "http://intel.invalid/mozilla.json"
        assert allow_insecure_http is True
        return b'{"schema_version":"foxclaw.mozilla.firefox_advisories.v1","product":"firefox","advisories":[]}\n'

    monkeypatch.setattr("foxclaw.intel.sync._read_http_payload", _fake_http_read)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "intel",
            "sync",
            "--source",
            "mozilla=http://intel.invalid/mozilla.json",
            "--allow-insecure-http",
            "--store-dir",
            str(tmp_path / "intel-store"),
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["sources"][0]["transport"] == "http"
    assert payload["sources"][0]["insecure_transport"] is True
