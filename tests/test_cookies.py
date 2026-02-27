from __future__ import annotations

import sqlite3
from pathlib import Path

from foxclaw.collect.cookies import audit_cookies_sqlite


def _create_cookies_db(
    path: Path,
    *,
    rows: list[tuple[str, str, int, int, int, int]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY,
            host TEXT,
            name TEXT,
            expiry INTEGER,
            isHttpOnly INTEGER,
            sameSite INTEGER,
            creationTime INTEGER
        )
        """
    )
    connection.executemany(
        """
        INSERT INTO moz_cookies (
            host,
            name,
            expiry,
            isHttpOnly,
            sameSite,
            creationTime
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    connection.commit()
    connection.close()


def test_audit_cookies_sqlite_missing_file_returns_empty(tmp_path: Path) -> None:
    result = audit_cookies_sqlite(tmp_path / "cookies.sqlite")

    assert result.opened_ro is False
    assert result.parse_error is None
    assert result.cookies_total == 0
    assert result.long_lived_cookie_count == 0
    assert result.samesite_none_sensitive_count == 0
    assert result.auth_cookie_missing_httponly_count == 0
    assert result.third_party_tracking_cookie_count == 0
    assert result.suspicious_signals == ()


def test_audit_cookies_sqlite_benign_payload_has_no_signals(tmp_path: Path) -> None:
    cookies_path = tmp_path / "cookies.sqlite"
    creation_epoch = 1_700_000_000
    _create_cookies_db(
        cookies_path,
        rows=[
            (
                ".example.com",
                "prefs",
                creation_epoch + (30 * 24 * 60 * 60),
                1,
                2,
                creation_epoch * 1_000_000,
            ),
            (
                ".example.com",
                "locale",
                creation_epoch + (7 * 24 * 60 * 60),
                1,
                1,
                creation_epoch * 1_000_000,
            ),
        ],
    )

    result = audit_cookies_sqlite(cookies_path)

    assert result.opened_ro is True
    assert result.parse_error is None
    assert result.cookies_total == 2
    assert result.long_lived_cookie_count == 0
    assert result.samesite_none_sensitive_count == 0
    assert result.auth_cookie_missing_httponly_count == 0
    assert result.third_party_tracking_cookie_count == 0
    assert result.suspicious_signals == ()


def test_audit_cookies_sqlite_flags_session_theft_and_tracking_signals(tmp_path: Path) -> None:
    cookies_path = tmp_path / "cookies.sqlite"
    creation_epoch = 1_700_000_000
    rows: list[tuple[str, str, int, int, int, int]] = [
        (
            ".example.com",
            "prefs",
            creation_epoch + (366 * 24 * 60 * 60),
            1,
            1,
            creation_epoch * 1_000_000,
        ),
        (
            ".secure-bank.example",
            "csrftoken",
            creation_epoch + (2 * 60 * 60),
            1,
            0,
            creation_epoch * 1_000_000,
        ),
        (
            ".accounts.example.com",
            "sessionid",
            creation_epoch + (2 * 60 * 60),
            0,
            1,
            creation_epoch * 1_000_000,
        ),
    ]
    for idx in range(11):
        rows.append(
            (
                ".doubleclick.net",
                f"track_{idx:02d}",
                creation_epoch + (2 * 60 * 60),
                1,
                1,
                creation_epoch * 1_000_000,
            )
        )

    _create_cookies_db(cookies_path, rows=rows)
    result = audit_cookies_sqlite(cookies_path)

    assert result.opened_ro is True
    assert result.parse_error is None
    assert result.cookies_total == 14
    assert result.long_lived_cookie_count == 1
    assert result.samesite_none_sensitive_count == 1
    assert result.auth_cookie_missing_httponly_count == 1
    assert result.third_party_tracking_cookie_count == 11
    assert len(result.suspicious_signals) >= 4
    observed_reasons = {
        reason
        for signal in result.suspicious_signals
        for reason in signal.reasons
    }
    assert {
        "long_lived_cookie",
        "samesite_none_sensitive_domain",
        "auth_cookie_missing_httponly",
        "third_party_tracking_cookie",
    } <= observed_reasons


def test_audit_cookies_sqlite_invalid_sqlite_reports_error(tmp_path: Path) -> None:
    cookies_path = tmp_path / "cookies.sqlite"
    cookies_path.write_bytes(b"not-a-sqlite-db")

    result = audit_cookies_sqlite(cookies_path)

    assert result.parse_error is not None
    assert result.cookies_total == 0
    assert result.suspicious_signals == ()
