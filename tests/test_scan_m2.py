from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from foxclaw.cli import app
from foxclaw.collect.filesystem import collect_file_permissions
from foxclaw.collect.prefs import collect_prefs
from foxclaw.collect.sqlite import collect_sqlite_quick_checks
from typer.testing import CliRunner


def _write_profiles_ini(base_dir: Path, content: str) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "profiles.ini").write_text(content, encoding="utf-8")


def _create_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def test_prefs_parser_supports_bool_int_string_and_userjs_precedence(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True)

    (profile_dir / "prefs.js").write_text(
        '\n'.join(
            [
                'user_pref("fox.bool", true);',
                'user_pref("fox.int", 42);',
                'user_pref("fox.str", "alpha");',
                'user_pref("fox.ignore", someExpr());',
            ]
        ),
        encoding="utf-8",
    )
    (profile_dir / "user.js").write_text(
        '\n'.join(
            [
                'user_pref("fox.int", 7);',
                'user_pref("fox.extra", "from-user");',
            ]
        ),
        encoding="utf-8",
    )

    evidence = collect_prefs(profile_dir)

    assert evidence.root["fox.bool"].value is True
    assert evidence.root["fox.bool"].raw_type == "bool"

    assert evidence.root["fox.int"].value == 7
    assert evidence.root["fox.int"].source == "user.js"
    assert evidence.root["fox.int"].raw_type == "int"

    assert evidence.root["fox.str"].value == "alpha"
    assert evidence.root["fox.str"].raw_type == "string"

    assert evidence.root["fox.extra"].value == "from-user"
    assert "fox.ignore" not in evidence.root


def test_permission_checker_flags_mode_644_as_group_world_readable(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True)

    target = profile_dir / "key4.db"
    target.write_text("secret", encoding="utf-8")
    target.chmod(0o644)

    evidence = collect_file_permissions(profile_dir)
    target_item = next(item for item in evidence if item.path == str(target))

    assert target_item.mode == "0644"
    assert target_item.group_readable is True
    assert target_item.world_readable is True
    assert target_item.recommended_chmod is not None
    assert target_item.recommended_chmod.startswith("chmod 600")


def test_sqlite_quick_check_on_temp_db_reports_ok(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True)

    places = profile_dir / "places.sqlite"
    cookies = profile_dir / "cookies.sqlite"
    _create_sqlite_db(places)
    _create_sqlite_db(cookies)

    checks = collect_sqlite_quick_checks(profile_dir)

    places_check = next(item for item in checks.checks if item.db_path == str(places))
    cookies_check = next(item for item in checks.checks if item.db_path == str(cookies))

    assert places_check.opened_ro is True
    assert cookies_check.opened_ro is True
    assert places_check.quick_check_result == "ok"
    assert cookies_check.quick_check_result == "ok"


def test_scan_json_schema_includes_expected_sections(
    tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "home"
    base_dir = home / ".mozilla" / "firefox"
    profile_rel = Path("Profiles/main.default-release")
    profile_dir = base_dir / profile_rel

    _write_profiles_ini(
        base_dir,
        """[Profile0]
Name=main
IsRelative=1
Path=Profiles/main.default-release
Default=1
""",
    )

    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "prefs.js").write_text(
        'user_pref("scan.pref", true);\n', encoding="utf-8"
    )
    (profile_dir / "prefs.js").chmod(0o600)

    (profile_dir / "key4.db").write_text("k", encoding="utf-8")
    (profile_dir / "key4.db").chmod(0o600)

    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")
    (profile_dir / "places.sqlite").chmod(0o600)
    (profile_dir / "cookies.sqlite").chmod(0o600)

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)

    assert payload["schema_version"] == "1.0.0"
    assert set(payload.keys()) >= {
        "schema_version",
        "generated_at",
        "profile",
        "prefs",
        "filesystem",
        "policies",
        "sqlite",
        "summary",
        "high_findings",
    }
    assert payload["profile"]["profile_id"] == "Profile0"
    assert "scan.pref" in payload["prefs"]
    assert "checks" in payload["sqlite"]
    assert set(payload["summary"].keys()) >= {
        "prefs_parsed",
        "sensitive_files_checked",
        "high_risk_perms_count",
        "policies_found",
        "sqlite_checks_total",
        "sqlite_non_ok_count",
        "findings_high_count",
    }


def test_scan_rejects_symlinked_profile_paths(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    target_prefs = tmp_path / "target-prefs.js"
    target_prefs.write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    try:
        (profile_dir / "prefs.js").symlink_to(target_prefs)
    except OSError as exc:
        pytest.skip(f"symlink creation not supported: {exc}")

    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "symlinked profile path is not allowed" in result.stdout


def test_scan_rejects_symlinked_sensitive_file_in_filesystem_collector(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")

    target_key4 = tmp_path / "target-key4.db"
    target_key4.write_text("key4", encoding="utf-8")
    try:
        (profile_dir / "key4.db").symlink_to(target_key4)
    except OSError as exc:
        pytest.skip(f"symlink creation not supported: {exc}")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "Operational error: symlinked profile path is not allowed" in result.stdout


def test_scan_rejects_symlinked_extension_artifact(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    extensions_dir = profile_dir / "extensions"
    extensions_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")
    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "bad-addon@example.com",
                        "type": "extension",
                        "active": True,
                        "location": "app-profile",
                        "path": "extensions/bad-addon@example.com.xpi",
                        "signedState": 2,
                    }
                ]
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    target_xpi = tmp_path / "target-bad-addon.xpi"
    target_xpi.write_text("not-a-real-xpi", encoding="utf-8")
    try:
        (extensions_dir / "bad-addon@example.com.xpi").symlink_to(target_xpi)
    except OSError as exc:
        pytest.skip(f"symlink creation not supported: {exc}")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "Operational error: symlinked profile path is not allowed" in result.stdout


def test_scan_rejects_extension_path_escape(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")
    (profile_dir / "extensions.json").write_text(
        json.dumps(
            {
                "addons": [
                    {
                        "id": "escape-addon@example.com",
                        "type": "extension",
                        "active": True,
                        "location": "app-profile",
                        "path": "../escape-addon@example.com.xpi",
                        "signedState": 2,
                    }
                ]
            },
            sort_keys=True,
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
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "Operational error: unsafe profile path escapes profile root" in result.stdout


def test_scan_rejects_symlinked_policy_path(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")

    policy_target = tmp_path / "policy-target.json"
    policy_target.write_text(json.dumps({"policies": {"DisableTelemetry": True}}), encoding="utf-8")
    policy_link = tmp_path / "policy-link.json"
    try:
        policy_link.symlink_to(policy_target)
    except OSError as exc:
        pytest.skip(f"symlink creation not supported: {exc}")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--profile",
            str(profile_dir),
            "--policy-path",
            str(policy_link),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "Operational error: symlinked profile path is not allowed" in result.stdout
