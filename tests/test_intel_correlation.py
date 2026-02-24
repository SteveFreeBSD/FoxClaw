from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from foxclaw.cli import app
from foxclaw.intel.sync import sync_sources
from typer.testing import CliRunner

INTEL_FIXTURE = Path("tests/fixtures/intel/mozilla_firefox_advisories.v1.json")
BLOCKLIST_FIXTURE = Path("tests/fixtures/intel/mozilla_extension_blocklist.v1.json")
AMO_EXTENSION_FIXTURE = Path("tests/fixtures/intel/amo_extension_intel.v1.json")
NVD_FIXTURE = Path("tests/fixtures/intel/nvd_cve_records.v1.json")
CVE_LIST_FIXTURE = Path("tests/fixtures/intel/cve_list_records.v1.json")
KEV_FIXTURE = Path("tests/fixtures/intel/cisa_kev.v1.json")
EPSS_FIXTURE = Path("tests/fixtures/intel/epss_scores.v1.json")


def _create_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def _write_xpi_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True))


def _prepare_profile(profile_dir: Path, *, last_version: str) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    (profile_dir / "compatibility.ini").write_text(
        "\n".join(
            [
                "[Compatibility]",
                f"LastVersion={last_version}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")


def _write_empty_ruleset(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "name: empty",
                "version: 1.0.0",
                "rules: []",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_scan_with_intel_snapshot_emits_correlated_cve_finding(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    sync_result = sync_sources(
        source_specs=[f"mozilla={INTEL_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="135.0_20260201000000/20260201000000")
    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            sync_result.manifest.snapshot_id,
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["summary"]["intel_matches_count"] == 1
    assert payload["intel"]["enabled"] is True
    assert payload["intel"]["snapshot_id"] == sync_result.manifest.snapshot_id
    assert payload["intel"]["profile_firefox_version"] == "135.0"
    assert {finding["id"] for finding in payload["findings"]} == {"FC-INTEL-CVE-2026-0001"}
    finding = payload["findings"][0]
    assert finding["risk_priority"] == "high"
    assert "severity_source:mozilla" in finding["risk_factors"]


def test_scan_with_multi_source_intel_applies_deterministic_merge_policy(
    tmp_path: Path,
) -> None:
    store_dir = tmp_path / "intel-store"
    sync_result = sync_sources(
        source_specs=[
            f"mozilla={INTEL_FIXTURE}",
            f"nvd={NVD_FIXTURE}",
            f"cvelist={CVE_LIST_FIXTURE}",
            f"kev={KEV_FIXTURE}",
        ],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="135.0_20260201000000/20260201000000")
    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            sync_result.manifest.snapshot_id,
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    finding = next(item for item in payload["findings"] if item["id"] == "FC-INTEL-CVE-2026-0001")
    assert finding["severity"] == "HIGH"
    assert finding["risk_priority"] == "critical"
    assert "kev_listed" in finding["risk_factors"]
    evidence = finding["evidence"]
    assert "intel_provenance_sources=cvelist,kev,mozilla,nvd" in evidence
    assert (
        "severity_resolution=selected:HIGH,source:mozilla,policy:mozilla>nvd>cve_list" in evidence
    )
    assert "severity_conflict=1, candidates=mozilla:HIGH;nvd:MEDIUM;cve_list:INFO" in evidence
    assert (
        "kev:kev:listed=1,vendor=Mozilla,product=Firefox,due_date=2026-03-07,ransomware_use=Unknown"
        in evidence
    )


def test_scan_with_epss_source_uplifts_risk_priority_deterministically(
    tmp_path: Path,
) -> None:
    store_dir = tmp_path / "intel-store"
    sync_sources(
        source_specs=[
            f"mozilla={INTEL_FIXTURE}",
            f"epss={EPSS_FIXTURE}",
        ],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="134.0_20260201000000/20260201000000")
    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "latest",
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    finding = next(item for item in payload["findings"] if item["id"] == "FC-INTEL-CVE-2026-0002")
    assert finding["severity"] == "MEDIUM"
    assert finding["risk_priority"] == "high"
    assert "epss_bucket:very_high" in finding["risk_factors"]
    assert "epss_score:0.9300" in finding["risk_factors"]
    assert "risk_priority=high" in finding["evidence"]


def test_scan_with_intel_snapshot_has_no_findings_when_version_not_affected(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    sync_sources(
        source_specs=[f"mozilla={INTEL_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="136.0_20260201000000/20260201000000")
    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "latest",
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["intel_matches_count"] == 0
    assert payload["findings"] == []


def test_scan_with_unknown_intel_snapshot_id_fails_operationally(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    sync_sources(
        source_specs=[f"mozilla={INTEL_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="135.0_20260201000000/20260201000000")
    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "deadbeef",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "intel snapshot id not found" in result.stdout


def test_scan_with_malformed_compatibility_ini_yields_intel_error_without_traceback(
    tmp_path: Path,
) -> None:
    store_dir = tmp_path / "intel-store"
    sync_sources(
        source_specs=[f"mozilla={INTEL_FIXTURE}"],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    # Missing section header to force ConfigParser parse failure.
    (profile_dir / "compatibility.ini").write_text(
        "LastVersion=135.0_20260201000000/20260201000000\n",
        encoding="utf-8",
    )
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")

    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "latest",
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["intel"]["enabled"] is True
    assert payload["intel"]["profile_firefox_version"] is None
    assert payload["intel"]["error"] == "compatibility.ini LastVersion was not available"
    assert payload["findings"] == []
    assert "Traceback" not in result.stdout


def test_scan_with_corrupted_intel_db_reports_operational_error_without_traceback(
    tmp_path: Path,
) -> None:
    store_dir = tmp_path / "intel-store"
    store_dir.mkdir(parents=True, exist_ok=True)

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="135.0_20260201000000/20260201000000")

    ruleset = tmp_path / "rules.yml"
    _write_empty_ruleset(ruleset)

    # Write malformed local intel artifacts: latest pointer resolves to a snapshot id,
    # but the sqlite db does not have the required schema.
    (store_dir / "latest.json").write_text(
        json.dumps({"schema_version": "1.0.0", "snapshot_id": "broken-snapshot"}),
        encoding="utf-8",
    )
    with sqlite3.connect(store_dir / "intel.db") as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS nonsense (id INTEGER PRIMARY KEY)")
        connection.commit()

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "latest",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "intel store query failed" in result.stdout
    assert "Traceback" not in result.stdout


def test_scan_with_blocklist_snapshot_flags_blocklisted_extension(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    sync_sources(
        source_specs=[
            f"mozilla={INTEL_FIXTURE}",
            f"blocklist={BLOCKLIST_FIXTURE}",
        ],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="136.0_20260201000000/20260201000000")
    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "blocked-all-versions@example.com",
                        "type": "extension",
                        "active": True,
                        "signedState": 2,
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: blocklist-only",
                "version: 1.0.0",
                "rules:",
                "  - id: EXT-BLOCK-001",
                "    title: active extensions must not be blocklisted",
                "    severity: HIGH",
                "    category: extensions",
                "    check:",
                "      extension_blocklisted_absent: {}",
                "    rationale: known-malicious extensions are disallowed",
                "    recommendation: remove blocklisted extension",
                "    confidence: high",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "latest",
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["findings"][0]["id"] == "EXT-BLOCK-001"
    assert payload["extensions"]["entries"][0]["blocklisted"] is True


def test_scan_with_amo_extension_intel_flags_risky_extension(tmp_path: Path) -> None:
    store_dir = tmp_path / "intel-store"
    sync_sources(
        source_specs=[
            f"mozilla={INTEL_FIXTURE}",
            f"amo={AMO_EXTENSION_FIXTURE}",
        ],
        store_dir=store_dir,
        normalize_json=True,
        cwd=Path.cwd(),
    )

    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir, last_version="136.0_20260201000000/20260201000000")

    extension_id = "risky-addon@example.com"
    xpi_path = profile_dir / "extensions" / f"{extension_id}.xpi"
    _write_xpi_manifest(
        xpi_path,
        {
            "manifest_version": 2,
            "name": "Risky Addon",
            "version": "1.0.0",
        },
    )
    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": extension_id,
                        "type": "extension",
                        "active": True,
                        "version": "1.0.0",
                        "signedState": 2,
                        "path": str(xpi_path),
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: extension-intel-risk",
                "version: 1.0.0",
                "rules:",
                "  - id: EXT-INTEL-001",
                "    title: extension intel risk should be absent",
                "    severity: HIGH",
                "    category: extensions",
                "    check:",
                "      extension_intel_reputation_absent:",
                "        min_level: high",
                "        include_unlisted: true",
                "    rationale: extension intel risk control",
                "    recommendation: remove risky extension",
                "    confidence: high",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--intel-store-dir",
            str(store_dir),
            "--intel-snapshot-id",
            "latest",
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    extension_entry = payload["extensions"]["entries"][0]
    assert extension_entry["intel_reputation_level"] == "high"
    assert extension_entry["intel_listed"] is False
    assert extension_entry["intel_source"] == "amo"
    assert extension_entry["intel_reason"] == "removed_for_policy_violation"
    assert payload["findings"][0]["id"] == "EXT-INTEL-001"
