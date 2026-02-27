from __future__ import annotations

import sqlite3
from pathlib import Path

from foxclaw.collect.certificates import audit_cert9_root_store


def _create_cert9_schema(path: Path) -> None:
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
    connection.commit()
    connection.close()


def test_audit_cert9_root_store_missing_db_returns_empty(tmp_path: Path) -> None:
    result = audit_cert9_root_store(tmp_path / "missing-cert9.db")

    assert result.opened_ro is False
    assert result.parse_error is None
    assert result.root_entries_total == 0
    assert result.suspicious_roots == ()


def test_audit_cert9_root_store_empty_db_is_benign(tmp_path: Path) -> None:
    cert9_path = tmp_path / "cert9.db"
    _create_cert9_schema(cert9_path)

    result = audit_cert9_root_store(cert9_path)

    assert result.opened_ro is True
    assert result.parse_error is None
    assert result.root_entries_total == 0
    assert result.suspicious_roots == ()


def test_audit_cert9_root_store_benign_builtin_root(tmp_path: Path) -> None:
    cert9_path = tmp_path / "cert9.db"
    _create_cert9_schema(cert9_path)
    connection = sqlite3.connect(cert9_path)
    connection.execute(
        "INSERT INTO nssPublic (id, a11, a102, a81, a90) VALUES (?, ?, ?, ?, ?)",
        (1, "Mozilla Root CA 1", "Mozilla Root CA 1", "2018-01-01T00:00:00+00:00", 1),
    )
    connection.execute(
        "INSERT INTO nssTrust (id, a11, a102, a81, a90) VALUES (?, ?, ?, ?, ?)",
        (1, "builtin trusted c,c,c", "", "", 1),
    )
    # Leaf certificate entry should not be counted as a root.
    connection.execute(
        "INSERT INTO nssPublic (id, a11, a102, a81, a90) VALUES (?, ?, ?, ?, ?)",
        (2, "example.com leaf", "Mozilla Root CA 1", "2025-01-01T00:00:00+00:00", 0),
    )
    connection.commit()
    connection.close()

    result = audit_cert9_root_store(cert9_path)

    assert result.opened_ro is True
    assert result.parse_error is None
    assert result.root_entries_total == 1
    assert result.suspicious_roots == ()


def test_audit_cert9_root_store_flags_rogue_root(tmp_path: Path) -> None:
    cert9_path = tmp_path / "cert9.db"
    _create_cert9_schema(cert9_path)
    connection = sqlite3.connect(cert9_path)
    connection.execute(
        "INSERT INTO nssPublic (id, a11, a102, a81, a90) VALUES (?, ?, ?, ?, ?)",
        (1, "Evil Corp Root CA", "Evil Corp Root CA", "2025-12-01T00:00:00+00:00", 1),
    )
    connection.execute(
        "INSERT INTO nssTrust (id, a11, a102, a81, a90) VALUES (?, ?, ?, ?, ?)",
        (1, "trusted c,c,c", "", "", 1),
    )
    connection.commit()
    connection.close()

    result = audit_cert9_root_store(cert9_path)

    assert result.opened_ro is True
    assert result.parse_error is None
    assert result.root_entries_total == 1
    assert len(result.suspicious_roots) == 1
    risk = result.suspicious_roots[0]
    assert risk.subject == "Evil Corp Root CA"
    assert risk.issuer == "Evil Corp Root CA"
    assert risk.not_before_utc == "2025-12-01T00:00:00+00:00"
    assert risk.reasons == ("non_default_trust_anchor", "recent_self_signed_root")
