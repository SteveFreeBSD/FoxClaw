"""Read-only cert9.db root CA audit helpers (WS-48)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from foxclaw.collect.safe_paths import sqlite_ro_uri

_DEFAULT_ROOT_MARKERS: tuple[str, ...] = (
    "mozilla",
    "microsoft",
    "apple",
    "google",
    "digicert",
    "globalsign",
    "let's encrypt",
    "letsencrypt",
    "amazon",
    "entrust",
    "sectigo",
    "comodo",
    "verisign",
    "geotrust",
    "godaddy",
    "quovadis",
    "trustwave",
    "d-trust",
    "buypass",
    "identrust",
)
_TRUST_ANCHOR_MARKERS: tuple[str, ...] = (
    "trusted",
    "trust_anchor",
    "anchor",
    "c,c,c",
    "ct,c,c",
    "tu,cu,tu",
)
_RECENT_ISSUANCE_REFERENCE_UTC = datetime(2026, 1, 1, tzinfo=UTC)
_RECENT_ISSUANCE_CUTOFF_UTC = _RECENT_ISSUANCE_REFERENCE_UTC - timedelta(days=365)


@dataclass(frozen=True, slots=True)
class CertRootRisk:
    """One suspicious root trust anchor entry from cert9.db."""

    subject: str
    issuer: str
    trust_flags: str
    not_before_utc: str | None
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Cert9AuditResult:
    """Deterministic cert9.db root CA audit output."""

    opened_ro: bool
    parse_error: str | None
    root_entries_total: int
    suspicious_roots: tuple[CertRootRisk, ...]


def audit_cert9_root_store(cert9_path: Path) -> Cert9AuditResult:
    """Audit cert9.db for suspicious root trust anchors."""
    if not cert9_path.is_file():
        return Cert9AuditResult(
            opened_ro=False,
            parse_error=None,
            root_entries_total=0,
            suspicious_roots=(),
        )

    uri = sqlite_ro_uri(cert9_path)
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=0.25, isolation_level=None)
    except sqlite3.Error as exc:
        return Cert9AuditResult(
            opened_ro=False,
            parse_error=str(exc),
            root_entries_total=0,
            suspicious_roots=(),
        )

    try:
        connection.execute("PRAGMA busy_timeout = 250;")
        connection.execute("PRAGMA query_only = ON;")
        connection.execute("PRAGMA temp_store = MEMORY;")
        root_rows = _load_root_rows(connection)
        suspicious_roots = tuple(
            item
            for item in (_classify_root_row(row) for row in root_rows)
            if item is not None
        )
    except sqlite3.Error as exc:
        return Cert9AuditResult(
            opened_ro=True,
            parse_error=str(exc),
            root_entries_total=0,
            suspicious_roots=(),
        )
    finally:
        connection.close()

    sorted_roots = tuple(
        sorted(
            suspicious_roots,
            key=lambda item: (
                item.subject.lower(),
                item.issuer.lower(),
                (item.not_before_utc or ""),
                item.trust_flags.lower(),
                ",".join(item.reasons),
            ),
        )
    )
    return Cert9AuditResult(
        opened_ro=True,
        parse_error=None,
        root_entries_total=len(root_rows),
        suspicious_roots=sorted_roots,
    )


def _load_root_rows(
    connection: sqlite3.Connection,
) -> list[tuple[str, str, str, str | None]]:
    table_names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name ASC"
        )
    }
    if "nssPublic" not in table_names:
        return []

    public_columns = _table_columns(connection, "nssPublic")
    if "id" not in public_columns or "a11" not in public_columns or "a102" not in public_columns:
        return []

    has_not_before = "a81" in public_columns
    has_root_flag = "a90" in public_columns
    has_trust = "nssTrust" in table_names and "a11" in _table_columns(connection, "nssTrust")

    fields = [
        "p.id AS cert_id",
        "p.a11 AS subject_name",
        "p.a102 AS issuer_name",
        "p.a81 AS not_before_utc" if has_not_before else "NULL AS not_before_utc",
        "p.a90 AS root_flag" if has_root_flag else "NULL AS root_flag",
        "t.a11 AS trust_flags" if has_trust else "NULL AS trust_flags",
    ]
    query = [
        f"SELECT {', '.join(fields)}",
        "FROM nssPublic p",
    ]
    if has_trust:
        query.append("LEFT JOIN nssTrust t ON t.id = p.id")
    query.append("ORDER BY p.id ASC")
    rows = connection.execute("\n".join(query)).fetchall()

    root_rows: list[tuple[str, str, str, str | None]] = []
    for _cert_id, subject_raw, issuer_raw, not_before_raw, root_flag_raw, trust_raw in rows:
        subject = _decode_db_text(subject_raw)
        issuer = _decode_db_text(issuer_raw)
        trust_flags = _decode_db_text(trust_raw)
        if not _is_root_entry(
            subject=subject,
            issuer=issuer,
            root_flag=_decode_db_int(root_flag_raw),
            trust_flags=trust_flags,
        ):
            continue
        not_before_utc = _normalize_not_before(_decode_db_text(not_before_raw))
        root_rows.append((subject, issuer, trust_flags, not_before_utc))
    return root_rows


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table_name});").fetchall()
    return {str(row[1]) for row in rows if len(row) > 1}


def _classify_root_row(row: tuple[str, str, str, str | None]) -> CertRootRisk | None:
    subject, issuer, trust_flags, not_before_utc = row
    subject_lower = subject.lower()
    issuer_lower = issuer.lower()
    trust_lower = trust_flags.lower()

    reasons: list[str] = []
    if _is_trust_anchor(trust_lower) and not _is_default_root_anchor(
        subject_lower=subject_lower,
        issuer_lower=issuer_lower,
        trust_lower=trust_lower,
    ):
        reasons.append("non_default_trust_anchor")

    if subject and issuer and subject_lower == issuer_lower and _is_recent_issuance(not_before_utc):
        reasons.append("recent_self_signed_root")

    if not reasons:
        return None
    return CertRootRisk(
        subject=subject,
        issuer=issuer,
        trust_flags=trust_flags,
        not_before_utc=not_before_utc,
        reasons=tuple(sorted(set(reasons))),
    )


def _is_root_entry(*, subject: str, issuer: str, root_flag: int | None, trust_flags: str) -> bool:
    if root_flag == 1:
        return True
    subject_lower = subject.lower()
    issuer_lower = issuer.lower()
    if subject and issuer and subject_lower == issuer_lower:
        return True
    if "root" in subject_lower:
        return True
    if _is_trust_anchor(trust_flags.lower()):
        return True
    return False


def _is_trust_anchor(trust_lower: str) -> bool:
    return any(token in trust_lower for token in _TRUST_ANCHOR_MARKERS)


def _is_default_root_anchor(
    *, subject_lower: str, issuer_lower: str, trust_lower: str
) -> bool:
    if "builtin" in trust_lower or "mozilla" in trust_lower:
        return True
    return any(
        marker in subject_lower or marker in issuer_lower for marker in _DEFAULT_ROOT_MARKERS
    )


def _is_recent_issuance(not_before_utc: str | None) -> bool:
    if not not_before_utc:
        return False
    parsed = _parse_datetime(not_before_utc)
    if parsed is None:
        return False
    return parsed >= _RECENT_ISSUANCE_CUTOFF_UTC


def _normalize_not_before(raw: str) -> str | None:
    value = raw.strip()
    if not value:
        return None
    parsed = _parse_datetime(value)
    return parsed.isoformat() if parsed is not None else value


def _parse_datetime(value: str) -> datetime | None:
    stripped = value.strip()
    if not stripped:
        return None

    if stripped.isdigit():
        try:
            return datetime.fromtimestamp(int(stripped), tz=UTC)
        except (OverflowError, ValueError):
            return None

    normalized = stripped.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        pass
    else:
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)

    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            parsed = datetime.strptime(stripped, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=UTC)
    return None


def _decode_db_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").replace("\x00", "").strip()
    return str(value).replace("\x00", "").strip()


def _decode_db_int(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="ignore").strip()
        if text.isdigit():
            return int(text)
        return None
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        return None
    return None
