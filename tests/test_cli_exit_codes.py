from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from foxclaw import cli as cli_module
from foxclaw.cli import app
from typer.testing import CliRunner


def _create_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def _prepare_profile(profile_dir: Path) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text(
        'user_pref("scan.pref", true);\n',
        encoding="utf-8",
    )
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")


def test_scan_exit_code_1_for_operational_error() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--json", "--sarif"])
    assert result.exit_code == 1


def test_scan_exit_code_0_when_no_high_findings(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir)

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: exit-code-zero",
                "version: 1.0.0",
                "rules:",
                "  - id: EXIT-INFO-001",
                "    title: info check",
                "    severity: INFO",
                "    category: preferences",
                "    check:",
                "      pref_exists:",
                "        key: missing.pref",
                "    rationale: test",
                "    recommendation: test",
                "    confidence: low",
            ]
        ),
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
            "--json",
        ],
    )
    assert result.exit_code == 0


def test_scan_exit_code_2_when_high_findings_exist(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir)
    (profile_dir / "key4.db").write_text("k", encoding="utf-8")
    (profile_dir / "key4.db").chmod(0o644)

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: exit-code-high",
                "version: 1.0.0",
                "rules:",
                "  - id: EXIT-HIGH-001",
                "    title: key4 strict perms",
                "    severity: HIGH",
                "    category: filesystem",
                "    check:",
                "      file_perm_strict:",
                "        key: key4",
                "    rationale: test",
                "    recommendation: test",
                "    confidence: high",
            ]
        ),
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
            "--json",
        ],
    )
    assert result.exit_code == 2


def test_scan_rejects_unc_profile_path_by_default() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            r"\\server\forensics\profile.default-release",
            "--json",
        ],
    )

    assert result.exit_code == 1
    if os.name != "nt":
        assert "UNC source profile paths are not directly accessible" in result.stdout


def test_scan_stages_share_profile_before_collection(tmp_path: Path, monkeypatch) -> None:
    source_profile = tmp_path / "source-profile"
    _prepare_profile(source_profile)

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: stage-share",
                "version: 1.0.0",
                "rules:",
                "  - id: STAGE-INFO-001",
                "    title: info check",
                "    severity: INFO",
                "    category: preferences",
                "    check:",
                "      pref_exists:",
                "        key: missing.pref",
                "    rationale: test",
                "    recommendation: test",
                "    confidence: low",
            ]
        ),
        encoding="utf-8",
    )

    output_json = tmp_path / "artifacts" / "foxclaw.json"
    stage_manifest = tmp_path / "artifacts" / "stage-manifest.json"
    staging_root = tmp_path / "staging-root"

    monkeypatch.setattr(
        cli_module,
        "is_windows_share_profile_source",
        lambda _path: True,
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(source_profile),
            "--ruleset",
            str(ruleset),
            "--staging-root",
            str(staging_root),
            "--stage-manifest-out",
            str(stage_manifest),
            "--output",
            str(output_json),
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert stage_manifest.exists()
    assert output_json.exists()

    manifest_payload = json.loads(stage_manifest.read_text(encoding="utf-8"))
    scan_payload = json.loads(output_json.read_text(encoding="utf-8"))

    assert manifest_payload["source_profile"] == str(source_profile.resolve())
    assert Path(manifest_payload["staged_profile"]).exists()
    assert str(staging_root) in manifest_payload["staged_profile"]
    assert scan_payload["profile"]["path"] == manifest_payload["staged_profile"]
    assert scan_payload["profile"]["path"] != str(source_profile.resolve())


def test_scan_share_staging_fails_closed_on_lock_marker(tmp_path: Path, monkeypatch) -> None:
    source_profile = tmp_path / "source-profile"
    _prepare_profile(source_profile)
    (source_profile / "parent.lock").write_text("locked\n", encoding="utf-8")

    monkeypatch.setattr(
        cli_module,
        "is_windows_share_profile_source",
        lambda _path: True,
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(source_profile),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "active-profile lock markers detected in source profile" in result.stdout


def test_scan_share_staging_allow_active_profile_records_lock_markers(
    tmp_path: Path, monkeypatch
) -> None:
    source_profile = tmp_path / "source-profile"
    _prepare_profile(source_profile)
    (source_profile / "parent.lock").write_text("locked\n", encoding="utf-8")

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: stage-share-lock",
                "version: 1.0.0",
                "rules:",
                "  - id: STAGE-INFO-002",
                "    title: info check",
                "    severity: INFO",
                "    category: preferences",
                "    check:",
                "      pref_exists:",
                "        key: missing.pref",
                "    rationale: test",
                "    recommendation: test",
                "    confidence: low",
            ]
        ),
        encoding="utf-8",
    )

    output_json = tmp_path / "artifacts" / "foxclaw.json"
    stage_manifest = tmp_path / "artifacts" / "stage-manifest.json"

    monkeypatch.setattr(
        cli_module,
        "is_windows_share_profile_source",
        lambda _path: True,
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(source_profile),
            "--allow-active-profile",
            "--stage-manifest-out",
            str(stage_manifest),
            "--ruleset",
            str(ruleset),
            "--output",
            str(output_json),
        ],
    )

    assert result.exit_code == 0, result.stdout
    manifest_payload = json.loads(stage_manifest.read_text(encoding="utf-8"))
    assert "parent.lock" in manifest_payload["source_lock_markers"]


def test_live_rejects_unc_profile_path_by_default() -> None:
    source_fixture = (
        Path(__file__).resolve().parent
        / "fixtures"
        / "intel"
        / "mozilla_firefox_advisories.v1.json"
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "live",
            "--source",
            f"example={source_fixture}",
            "--profile",
            r"\\server\forensics\profile.default-release",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "UNC profile paths are disabled by default" in result.stdout
