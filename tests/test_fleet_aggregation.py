from __future__ import annotations

import json
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


def _prepare_profile(profile_dir: Path, *, weak_perms: bool) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text(
        'user_pref("scan.pref", true);\n',
        encoding="utf-8",
    )
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")
    (profile_dir / "key4.db").write_text("k", encoding="utf-8")
    (profile_dir / "key4.db").chmod(0o644 if weak_perms else 0o600)


def _write_ruleset(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "name: fleet-tests",
                "version: 1.0.0",
                "rules:",
                "  - id: FLEET-FILE-001",
                "    title: strict key4 perms",
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


def test_fleet_aggregate_json_contract_and_exit_code(tmp_path: Path) -> None:
    secure_profile = tmp_path / "profile-secure"
    weak_profile = tmp_path / "profile-weak"
    _prepare_profile(secure_profile, weak_perms=False)
    _prepare_profile(weak_profile, weak_perms=True)

    ruleset = tmp_path / "fleet-rules.yml"
    _write_ruleset(ruleset)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "fleet",
            "aggregate",
            "--profile",
            str(secure_profile),
            "--profile",
            str(weak_profile),
            "--ruleset",
            str(ruleset),
            "--json",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["fleet_schema_version"] == "1.0.0"

    assert payload["aggregate"]["profiles_total"] == 2
    assert payload["aggregate"]["profiles_with_findings"] == 1
    assert payload["aggregate"]["profiles_with_high_findings"] == 1
    assert payload["aggregate"]["findings_total"] == 1
    assert payload["aggregate"]["findings_high_count"] == 1
    assert payload["aggregate"]["findings_medium_count"] == 0
    assert payload["aggregate"]["findings_info_count"] == 0
    assert payload["aggregate"]["unique_rule_ids"] == ["FLEET-FILE-001"]

    assert len(payload["host"]["host_id"]) == 64
    assert len(payload["profiles"]) == 2
    assert len(payload["finding_records"]) == 1

    profile_uids = {item["identity"]["profile_uid"] for item in payload["profiles"]}
    assert all(len(item) == 64 for item in profile_uids)
    assert len(profile_uids) == 2

    record = payload["finding_records"][0]
    assert record["host_id"] == payload["host"]["host_id"]
    assert record["profile_uid"] in profile_uids
    assert record["rule_id"] == "FLEET-FILE-001"
    assert record["severity"] == "HIGH"


def test_fleet_aggregate_json_is_deterministic(tmp_path: Path) -> None:
    profile_a = tmp_path / "profile-a"
    profile_b = tmp_path / "profile-b"
    _prepare_profile(profile_a, weak_perms=False)
    _prepare_profile(profile_b, weak_perms=True)

    ruleset = tmp_path / "fleet-rules.yml"
    _write_ruleset(ruleset)

    cmd = [
        "fleet",
        "aggregate",
        "--profile",
        str(profile_a),
        "--profile",
        str(profile_b),
        "--ruleset",
        str(ruleset),
        "--json",
    ]

    runner = CliRunner()
    first = runner.invoke(app, cmd)
    second = runner.invoke(app, cmd)

    assert first.exit_code == 2
    assert second.exit_code == 2
    assert first.stdout == second.stdout
