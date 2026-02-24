from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from foxclaw.cli import app
from foxclaw.collect.credentials import collect_credential_exposure
from typer.testing import CliRunner


def _create_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def _create_formhistory_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS moz_formhistory (
            id INTEGER PRIMARY KEY,
            fieldname TEXT NOT NULL,
            value TEXT NOT NULL
        )
        """
    )
    connection.executemany(
        "INSERT INTO moz_formhistory(fieldname, value) VALUES (?, ?)",
        [
            ("password", "example-pass"),
            ("email", "user@example.com"),
            ("searchbar-history", "firefox profile"),
        ],
    )
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


def test_collect_credential_exposure_parses_logins_and_formhistory(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "logins.json").write_text(
        json.dumps(
            {
                "logins": [
                    {
                        "id": 1,
                        "hostname": "https://accounts.example.com",
                        "encryptedUsername": "enc-user-1",
                        "encryptedPassword": "enc-cred-1",  # pragma: allowlist secret
                    },
                    {
                        "id": 2,
                        "hostname": "http://legacy.example.net",
                        "encryptedUsername": "enc-user-2",
                        "encryptedPassword": "enc-cred-2",  # pragma: allowlist secret
                    },
                ],
                "potentiallyVulnerablePasswords": [
                    {"guid": "login-guid-1"},
                    {"guid": "login-guid-2"},
                ],
                "dismissedBreachAlertsByLoginGUID": {
                    "login-guid-3": {"timeLastAlertShown": 1739385600}
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    _create_formhistory_db(profile_dir / "formhistory.sqlite")

    evidence = collect_credential_exposure(profile_dir)

    assert evidence.logins_present is True
    assert evidence.saved_logins_count == 2
    assert evidence.vulnerable_passwords_count == 2
    assert evidence.dismissed_breach_alerts_count == 1
    assert evidence.insecure_http_login_count == 1
    assert evidence.logins_parse_error is None

    assert evidence.formhistory_present is True
    assert evidence.formhistory_opened_ro is True
    assert evidence.formhistory_password_field_count == 1
    assert evidence.formhistory_credential_field_count == 2
    assert evidence.formhistory_parse_error is None


def test_collect_credential_exposure_reports_invalid_logins_json(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "logins.json").write_text("{not valid json", encoding="utf-8")

    evidence = collect_credential_exposure(profile_dir)

    assert evidence.logins_present is True
    assert evidence.logins_parse_error is not None
    assert evidence.saved_logins_count == 0
    assert evidence.vulnerable_passwords_count == 0
    assert evidence.dismissed_breach_alerts_count == 0


def test_scan_credential_metric_high_finding_and_exit_code(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    _prepare_profile(profile_dir)
    (profile_dir / "logins.json").write_text(
        json.dumps(
            {
                "logins": [
                    {
                        "id": 1,
                        "hostname": "https://accounts.example.com",
                        "encryptedUsername": "enc-user-1",
                        "encryptedPassword": "enc-cred-1",  # pragma: allowlist secret
                    }
                ],
                "potentiallyVulnerablePasswords": [{"guid": "login-guid-1"}],
            }
        ),
        encoding="utf-8",
    )

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: credentials-high",
                "version: 1.0.0",
                "rules:",
                "  - id: CRED-HIGH-001",
                "    title: vulnerable password count must be zero",
                "    severity: HIGH",
                "    category: credentials",
                "    check:",
                "      credential_metric_max:",
                "        metric: vulnerable_passwords_count",
                "        max: 0",
                "    rationale: leaked credentials are high risk",
                "    recommendation: rotate vulnerable passwords immediately",
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
    payload = json.loads(result.stdout)
    assert payload["credentials"]["vulnerable_passwords_count"] == 1
    assert payload["summary"]["findings_high_count"] == 1
    assert payload["findings"][0]["id"] == "CRED-HIGH-001"
