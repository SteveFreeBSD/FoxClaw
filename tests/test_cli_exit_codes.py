from __future__ import annotations

import sqlite3
from pathlib import Path

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
    assert "UNC profile paths are disabled by default" in result.stdout


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
