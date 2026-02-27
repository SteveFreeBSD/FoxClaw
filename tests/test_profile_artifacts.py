from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from foxclaw.cli import app
from foxclaw.collect.artifacts import _HASH_BYTES_CAP, collect_profile_artifacts
from foxclaw.collect.sqlite import collect_sqlite_quick_checks
from typer.testing import CliRunner


def _create_sqlite_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def _create_cert9_db(path: Path, *, rows: list[tuple[str, str, str, int, str]]) -> None:
    """Create a minimal cert9-like schema with deterministic test rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE nssPublic (
            id INTEGER PRIMARY KEY,
            a11 BLOB,
            a102 BLOB,
            a81 BLOB,
            a90 INTEGER
        );
        CREATE TABLE nssTrust (
            id INTEGER PRIMARY KEY,
            a11 BLOB,
            a102 BLOB,
            a81 BLOB,
            a90 INTEGER
        );
        """
    )
    for idx, (subject, issuer, not_before_utc, root_flag, trust_flags) in enumerate(rows, start=1):
        connection.execute(
            "INSERT INTO nssPublic (id, a11, a102, a81, a90) VALUES (?, ?, ?, ?, ?)",
            (idx, subject, issuer, not_before_utc, root_flag),
        )
        connection.execute(
            "INSERT INTO nssTrust (id, a11, a102, a81, a90) VALUES (?, ?, ?, ?, ?)",
            (idx, trust_flags, "", "", root_flag),
        )
    connection.commit()
    connection.close()


def test_collect_profile_artifacts_collects_hashes_and_key_fields(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    handlers_path = profile_dir / "handlers.json"
    handlers_payload = {
        "defaultHandlersVersion": 1,
        "mimeTypes": {"text/plain": {"action": 2}},
        "schemes": {"mailto": {"action": 4}},
    }
    handlers_path.write_text(json.dumps(handlers_payload), encoding="utf-8")

    containers_path = profile_dir / "containers.json"
    containers_path.write_text(
        json.dumps({"version": 5, "identities": [{"name": "Work"}, {"name": "Lab"}]}),
        encoding="utf-8",
    )

    compatibility_path = profile_dir / "compatibility.ini"
    compatibility_path.write_text(
        "\n".join(
            [
                "[Compatibility]",
                "LastVersion=140.0.2_20260220000000/20260220000000",
                "LastOSABI=Linux_x86_64-gcc3",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    search_path = profile_dir / "search.json.mozlz4"
    search_path.write_bytes(b"mozLz40\0fixture")

    evidence = collect_profile_artifacts(profile_dir)
    entries = {entry.rel_path: entry for entry in evidence.entries}

    assert set(entries) == {
        "compatibility.ini",
        "containers.json",
        "handlers.json",
        "search.json.mozlz4",
    }

    handlers = entries["handlers.json"]
    assert handlers.parse_status == "parsed"
    assert handlers.key_values["default_handlers_version"] == "1"
    assert handlers.key_values["mime_types_count"] == "1"
    assert handlers.key_values["schemes_count"] == "1"
    assert handlers.key_values["suspicious_local_exec_count"] == "0"
    assert handlers.sha256 == hashlib.sha256(handlers_path.read_bytes()).hexdigest()

    containers = entries["containers.json"]
    assert containers.parse_status == "parsed"
    assert containers.key_values["identities_count"] == "2"
    assert containers.key_values["version"] == "5"

    compatibility = entries["compatibility.ini"]
    assert compatibility.parse_status == "parsed"
    assert compatibility.key_values["last_version"].startswith("140.0.2_")
    assert compatibility.key_values["last_osabi"] == "Linux_x86_64-gcc3"

    search = entries["search.json.mozlz4"]
    assert search.parse_status == "metadata_only"
    assert search.sha256 == hashlib.sha256(search_path.read_bytes()).hexdigest()


def test_collect_sqlite_quick_checks_include_additional_existing_dbs(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")
    _create_sqlite_db(profile_dir / "permissions.sqlite")

    checks = collect_sqlite_quick_checks(profile_dir)
    observed_names = {Path(item.db_path).name for item in checks.checks}

    assert {"places.sqlite", "cookies.sqlite", "permissions.sqlite"} <= observed_names
    assert all(item.quick_check_result == "ok" for item in checks.checks)


def test_collect_profile_artifacts_parses_cert9_db_root_risks(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    _create_cert9_db(
        profile_dir / "cert9.db",
        rows=[
            ("Mozilla Root CA 1", "Mozilla Root CA 1", "2018-01-01T00:00:00+00:00", 1, "builtin c,c,c"),
            ("Evil Corp Root CA", "Evil Corp Root CA", "2025-12-01T00:00:00+00:00", 1, "trusted c,c,c"),
        ],
    )

    evidence = collect_profile_artifacts(profile_dir)
    cert9 = {entry.rel_path: entry for entry in evidence.entries}["cert9.db"]

    assert cert9.parse_status == "parsed"
    assert cert9.key_values["root_ca_entries_count"] == "2"
    assert cert9.key_values["suspicious_root_ca_count"] == "1"
    assert json.loads(cert9.key_values["suspicious_root_ca_entries"]) == [
        {
            "issuer": "Evil Corp Root CA",
            "not_before_utc": "2025-12-01T00:00:00+00:00",
            "reasons": ["non_default_trust_anchor", "recent_self_signed_root"],
            "subject": "Evil Corp Root CA",
            "trust_flags": "trusted c,c,c",
        }
    ]


def test_collect_profile_artifacts_parses_pkcs11_module_risks(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "pkcs11.txt").write_text(
        "\n".join(
            [
                "name=NSS Internal PKCS #11 Module",
                "library=",
                "",
                "name=Injected Module",
                "library=/tmp/evilpkcs11.so",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    evidence = collect_profile_artifacts(profile_dir)
    pkcs11 = {entry.rel_path: entry for entry in evidence.entries}["pkcs11.txt"]

    assert pkcs11.parse_status == "parsed"
    assert pkcs11.key_values["pkcs11_modules_count"] == "2"
    assert pkcs11.key_values["suspicious_pkcs11_module_count"] == "1"
    assert json.loads(pkcs11.key_values["suspicious_pkcs11_modules"]) == [
        {
            "library_path": "/tmp/evilpkcs11.so",
            "name": "Injected Module",
            "reasons": ["non_standard_library_path"],
        }
    ]


def test_collect_profile_artifacts_parses_sessionstore_sensitive_data(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "sessionstore.jsonlz4").write_text(
        json.dumps(
            {
                "selectedWindow": 1,
                "windows": [
                    {
                        "tabs": [
                            {
                                "entries": [
                                    {
                                        "formdata": {
                                            "id": {
                                                "authToken": "tok_abc123",
                                                "password": "hunter2",
                                            }
                                        },
                                        "url": "https://example.com/account",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    evidence = collect_profile_artifacts(profile_dir)
    session = {entry.rel_path: entry for entry in evidence.entries}["sessionstore.jsonlz4"]

    assert session.parse_status == "parsed"
    assert session.key_values["session_restore_enabled"] == "1"
    assert session.key_values["session_windows_count"] == "1"
    assert session.key_values["session_sensitive_entry_count"] == "2"
    assert json.loads(session.key_values["session_sensitive_entries"]) == [
        {
            "kind": "auth_token_field",
            "path": "$.windows[0].tabs[0].entries[0].formdata.id.authToken",
        },
        {
            "kind": "password_field",
            "path": "$.windows[0].tabs[0].entries[0].formdata.id.password",
        },
    ]


def test_collect_profile_artifacts_skips_hash_for_large_files(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    large_artifact = profile_dir / "sessionstore.jsonlz4"
    with large_artifact.open("wb") as handle:
        handle.truncate(_HASH_BYTES_CAP + 1)

    evidence = collect_profile_artifacts(profile_dir)
    entries = {entry.rel_path: entry for entry in evidence.entries}
    artifact = entries["sessionstore.jsonlz4"]

    assert artifact.sha256 is None
    assert artifact.key_values["hash_skipped"] == "size_cap"
    assert artifact.parse_status == "metadata_only"


def test_collect_profile_artifacts_includes_hsts_txt_and_bin(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    hsts_txt = profile_dir / "SiteSecurityServiceState.txt"
    hsts_bin = profile_dir / "SiteSecurityServiceState.bin"
    hsts_txt.write_text("example.com:HSTS\n", encoding="utf-8")
    hsts_bin.write_bytes(b"\x00legacy-binary-state")

    evidence = collect_profile_artifacts(profile_dir)
    entries = {entry.rel_path: entry for entry in evidence.entries}

    assert "SiteSecurityServiceState.txt" in entries
    assert "SiteSecurityServiceState.bin" in entries
    assert entries["SiteSecurityServiceState.txt"].sha256 == hashlib.sha256(
        hsts_txt.read_bytes()
    ).hexdigest()
    assert entries["SiteSecurityServiceState.bin"].sha256 == hashlib.sha256(
        hsts_bin.read_bytes()
    ).hexdigest()


def test_collect_profile_artifacts_flags_suspicious_protocol_handlers(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "handlers.json").write_text(
        json.dumps(
            {
                "schemes": {
                    "benign": {
                        "ask": True,
                        "handlers": [{"path": "C:\\Program Files\\App\\app.exe"}],
                    },
                    "dangerous": {
                        "ask": False,
                        "handlers": [{"path": "C:\\Windows\\System32\\cmd.exe /c whoami"}],
                    },
                    "dangerous-posix": {
                        "ask": False,
                        "handlers": [{"path": "/tmp/launcher.sh"}],
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    evidence = collect_profile_artifacts(profile_dir)
    handlers = {entry.rel_path: entry for entry in evidence.entries}["handlers.json"]

    assert handlers.key_values["suspicious_local_exec_count"] == "2"
    assert json.loads(handlers.key_values["suspicious_local_exec_handlers"]) == [
        {"path": "C:\\Windows\\System32\\cmd.exe /c whoami", "scheme": "dangerous"},
        {"path": "/tmp/launcher.sh", "scheme": "dangerous-posix"},
    ]


def test_scan_rejects_symlinked_artifact_path(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    (profile_dir / "prefs.js").write_text('user_pref("scan.pref", true);\n', encoding="utf-8")
    _create_sqlite_db(profile_dir / "places.sqlite")
    _create_sqlite_db(profile_dir / "cookies.sqlite")

    target_handlers = tmp_path / "handlers-target.json"
    target_handlers.write_text("{}", encoding="utf-8")
    try:
        (profile_dir / "handlers.json").symlink_to(target_handlers)
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
    assert "Operational error: symlinked profile path is not allowed:" in result.stdout
