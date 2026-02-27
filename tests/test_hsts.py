from __future__ import annotations

import sqlite3
from pathlib import Path

from foxclaw.collect.hsts import audit_hsts_state


def _create_places_db(path: Path, *, urls: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT
        )
        """
    )
    connection.executemany(
        "INSERT INTO moz_places (url) VALUES (?)",
        [(url,) for url in urls],
    )
    connection.commit()
    connection.close()


def test_audit_hsts_state_missing_file_returns_empty(tmp_path: Path) -> None:
    result = audit_hsts_state(tmp_path / "SiteSecurityServiceState.txt")

    assert result.parse_error is None
    assert result.entries == ()
    assert result.critical_hosts_expected == ()
    assert result.missing_critical_hosts == ()
    assert result.malformed_line_count == 0
    assert result.suspicious_signals == ()


def test_audit_hsts_state_passes_when_critical_hosts_are_covered(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    _create_places_db(
        profile_dir / "places.sqlite",
        urls=[
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://example.com/",
        ],
    )
    (profile_dir / "SiteSecurityServiceState.txt").write_text(
        "microsoftonline.com:443\tHSTS\t0\t1700000000000\t1690000000000\t1\t1\t0\n",
        encoding="utf-8",
    )

    result = audit_hsts_state(profile_dir / "SiteSecurityServiceState.txt")

    assert result.parse_error is None
    assert [entry.host for entry in result.entries] == ["microsoftonline.com"]
    assert result.critical_hosts_expected == ("login.microsoftonline.com",)
    assert result.missing_critical_hosts == ()
    assert result.suspicious_signals == ()


def test_audit_hsts_state_flags_selective_deletion_for_missing_critical_host(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    _create_places_db(
        profile_dir / "places.sqlite",
        urls=[
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://secure.microsoftonline.com/account",
        ],
    )
    (profile_dir / "SiteSecurityServiceState.txt").write_text(
        "login.microsoftonline.com:443\tHSTS\t0\t1700000000000\t1690000000000\t0\t1\t0\n",
        encoding="utf-8",
    )

    result = audit_hsts_state(profile_dir / "SiteSecurityServiceState.txt")

    assert result.parse_error is None
    assert result.missing_critical_hosts == ("secure.microsoftonline.com",)
    assert [(item.host, item.reasons) for item in result.suspicious_signals] == [
        (
            "secure.microsoftonline.com",
            ("missing_critical_hsts_entry", "selective_hsts_entry_deletion"),
        )
    ]


def test_audit_hsts_state_flags_truncation_pattern(tmp_path: Path) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)
    _create_places_db(
        profile_dir / "places.sqlite",
        urls=[
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://secure.wellsfargo.com/",
            "https://mail.proton.me/",
        ],
    )
    # Intentionally omit trailing newline and keep very few entries to mimic truncation.
    (profile_dir / "SiteSecurityServiceState.txt").write_text(
        "example.com:443\tHSTS\t0\t1700000000000\t1690000000000\t1\t1\t0",
        encoding="utf-8",
    )

    result = audit_hsts_state(profile_dir / "SiteSecurityServiceState.txt")

    assert result.parse_error is None
    assert len(result.missing_critical_hosts) == 3
    observed = {item.host: item.reasons for item in result.suspicious_signals}
    assert observed["<global>"] == ("hsts_file_truncation_pattern",)
    assert observed["login.microsoftonline.com"] == ("missing_critical_hsts_entry",)
    assert observed["mail.proton.me"] == ("missing_critical_hsts_entry",)
    assert observed["secure.wellsfargo.com"] == ("missing_critical_hsts_entry",)
