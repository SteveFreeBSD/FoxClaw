"""Read-only credential exposure signals from Firefox profile artifacts."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from urllib.parse import quote

from foxclaw.collect.safe_paths import iter_safe_profile_files
from foxclaw.models import CredentialEvidence

_CREDENTIAL_ARTIFACTS: tuple[str, ...] = (
    "logins.json",
    "formhistory.sqlite",
)


def collect_credential_exposure(profile_dir: Path) -> CredentialEvidence:
    """Collect password leak and credential exposure metrics from profile artifacts."""
    evidence = CredentialEvidence()
    safe_paths = {
        rel_path: resolved_path
        for rel_path, resolved_path in iter_safe_profile_files(profile_dir, _CREDENTIAL_ARTIFACTS)
    }

    logins_path = safe_paths["logins.json"]
    if logins_path.is_file():
        evidence.logins_present = True
        (
            evidence.saved_logins_count,
            evidence.vulnerable_passwords_count,
            evidence.dismissed_breach_alerts_count,
            evidence.insecure_http_login_count,
            evidence.logins_parse_error,
        ) = _collect_logins_metrics(logins_path)

    formhistory_path = safe_paths["formhistory.sqlite"]
    if formhistory_path.is_file():
        evidence.formhistory_present = True
        (
            evidence.formhistory_opened_ro,
            evidence.formhistory_password_field_count,
            evidence.formhistory_credential_field_count,
            evidence.formhistory_parse_error,
        ) = _collect_formhistory_metrics(formhistory_path)

    return evidence


def _collect_logins_metrics(path: Path) -> tuple[int, int, int, int, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return 0, 0, 0, 0, str(exc)

    if not isinstance(payload, dict):
        return 0, 0, 0, 0, "top-level JSON is not an object"

    logins_obj = payload.get("logins")
    logins = [item for item in logins_obj if isinstance(item, dict)] if isinstance(logins_obj, list) else []

    vulnerable_count = _count_list(payload.get("potentiallyVulnerablePasswords"))
    dismissed_count = _count_collection(payload.get("dismissedBreachAlertsByLoginGUID"))
    insecure_http_count = sum(
        1
        for item in logins
        if isinstance(item.get("hostname"), str)
        and item["hostname"].strip().lower().startswith("http://")
    )

    return len(logins), vulnerable_count, dismissed_count, insecure_http_count, None


def _collect_formhistory_metrics(path: Path) -> tuple[bool, int, int, str | None]:
    uri = _sqlite_ro_uri(path)
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=0.25, isolation_level=None)
    except sqlite3.Error as exc:
        return False, 0, 0, str(exc)

    try:
        connection.execute("PRAGMA busy_timeout = 250;")
        connection.execute("PRAGMA query_only = ON;")
        connection.execute("PRAGMA temp_store = MEMORY;")

        password_field_count = _query_count(
            connection,
            """
            SELECT COUNT(*)
            FROM moz_formhistory
            WHERE lower(fieldname) LIKE ?
               OR lower(fieldname) LIKE ?
            """,
            ("%pass%", "%pwd%"),
        )
        credential_field_count = _query_count(
            connection,
            """
            SELECT COUNT(*)
            FROM moz_formhistory
            WHERE lower(fieldname) LIKE ?
               OR lower(fieldname) LIKE ?
               OR lower(fieldname) LIKE ?
               OR lower(fieldname) LIKE ?
               OR lower(fieldname) LIKE ?
            """,
            ("%pass%", "%pwd%", "%user%", "%email%", "%login%"),
        )
    except sqlite3.Error as exc:
        return True, 0, 0, str(exc)
    finally:
        connection.close()

    return True, password_field_count, credential_field_count, None


def _query_count(
    connection: sqlite3.Connection, query: str, params: tuple[str, ...]
) -> int:
    row = connection.execute(query, params).fetchone()
    if row is None or not row:
        return 0
    value = row[0]
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return 0


def _count_list(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def _count_collection(value: object) -> int:
    if isinstance(value, dict):
        return len(value)
    if isinstance(value, list):
        return len(value)
    return 0


def _sqlite_ro_uri(db_path: Path) -> str:
    quoted = quote(str(db_path), safe="/")
    return f"file:{quoted}?mode=ro&immutable=1"
