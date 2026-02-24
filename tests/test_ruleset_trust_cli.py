from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from foxclaw.cli import app
from typer.testing import CliRunner


def _normalized_output(text: str) -> str:
    return " ".join(text.split())


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


def _write_ruleset(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "name: trust-cli-tests",
                "version: 1.0.0",
                "rules:",
                "  - id: TRUST-CLI-001",
                "    title: trust cli info check",
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


def _write_manifest(
    *,
    path: Path,
    ruleset_path: Path,
    sha256: str,
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "keys": [],
                "rulesets": [
                    {
                        "path": str(ruleset_path),
                        "sha256": sha256,
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def test_scan_with_trust_manifest_sha256_match_succeeds(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir)

    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        path=manifest,
        ruleset_path=ruleset,
        sha256=hashlib.sha256(ruleset.read_bytes()).hexdigest(),
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
            "--ruleset-trust-manifest",
            str(manifest),
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings_info_count"] == 1
    assert payload["summary"]["findings_high_count"] == 0


def test_scan_with_trust_manifest_sha256_mismatch_fails_closed(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir)

    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        path=manifest,
        ruleset_path=ruleset,
        sha256="0" * 64,
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
            "--ruleset-trust-manifest",
            str(manifest),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "sha256 mismatch" in _normalized_output(result.stdout)


def test_scan_with_required_signatures_without_signatures_fails_closed(
    tmp_path: Path,
) -> None:
    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir)

    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        path=manifest,
        ruleset_path=ruleset,
        sha256=hashlib.sha256(ruleset.read_bytes()).hexdigest(),
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
            "--ruleset-trust-manifest",
            str(manifest),
            "--require-ruleset-signatures",
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "signatures are required" in _normalized_output(result.stdout)


def test_fleet_aggregate_with_trust_manifest_mismatch_fails_closed(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir)

    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)

    manifest = tmp_path / "ruleset-trust.json"
    _write_manifest(
        path=manifest,
        ruleset_path=ruleset,
        sha256="0" * 64,
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "fleet",
            "aggregate",
            "--profile",
            str(profile_dir),
            "--ruleset",
            str(ruleset),
            "--ruleset-trust-manifest",
            str(manifest),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "sha256 mismatch" in _normalized_output(result.stdout)


def test_scan_with_trust_manifest_signature_threshold_fail_is_operational_error(
    tmp_path: Path,
) -> None:
    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir)

    ruleset = tmp_path / "rules.yml"
    _write_ruleset(ruleset)
    sha256 = hashlib.sha256(ruleset.read_bytes()).hexdigest()

    manifest = tmp_path / "ruleset-trust.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.1.0",
                "keys": [],
                "rulesets": [
                    {
                        "path": str(ruleset),
                        "sha256": sha256,
                        "min_valid_signatures": 2,
                    }
                ],
            },
            indent=2,
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
            "--ruleset-trust-manifest",
            str(manifest),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "min_valid_signatures is configured as 2" in _normalized_output(result.stdout)
