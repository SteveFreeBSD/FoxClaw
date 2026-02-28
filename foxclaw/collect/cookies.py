"""Read-only cookies.sqlite security posture audit helpers (WS-52)."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from foxclaw.collect.safe_paths import sqlite_ro_uri

_COOKIE_LIFETIME_THRESHOLD_SECONDS = 365 * 24 * 60 * 60
_TRACKING_COOKIE_EXCESS_THRESHOLD = 10
_SENSITIVE_DOMAIN_TOKENS: tuple[str, ...] = (
    "account",
    "admin",
    "auth",
    "bank",
    "finance",
    "idp",
    "inbox",
    "login",
    "mail",
    "pay",
    "portal",
    "secure",
    "wallet",
)
_AUTH_COOKIE_NAME_RE = re.compile(r"(?i)(?:^|[_-])(auth|session|sess|sid|token|csrf|jwt|sso|bearer)")
_TRACKER_HOST_SUFFIXES: tuple[str, ...] = (
    "2mdn.net",
    "adnxs.com",
    "adsrvr.org",
    "criteo.com",
    "doubleclick.net",
    "google-analytics.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "mathtag.com",
    "omtrdc.net",
    "outbrain.com",
    "quantserve.com",
    "scorecardresearch.com",
    "taboola.com",
)


@dataclass(frozen=True, slots=True)
class CookieEntry:
    """One normalized cookie row from cookies.sqlite."""

    host: str
    name: str
    expiry_epoch: int | None
    creation_epoch: int | None
    is_http_only: bool
    same_site: str | None


@dataclass(frozen=True, slots=True)
class CookieSecuritySignal:
    """One suspicious cookie-security posture signal."""

    host: str
    name: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CookieAuditResult:
    """Deterministic cookies.sqlite audit output."""

    opened_ro: bool
    parse_error: str | None
    cookies_total: int
    long_lived_cookie_count: int
    samesite_none_sensitive_count: int
    auth_cookie_missing_httponly_count: int
    third_party_tracking_cookie_count: int
    suspicious_signals: tuple[CookieSecuritySignal, ...]


def audit_cookies_sqlite(cookies_path: Path) -> CookieAuditResult:
    """Audit cookies.sqlite for session-theft and tracking posture signals."""
    if not cookies_path.is_file():
        return CookieAuditResult(
            opened_ro=False,
            parse_error=None,
            cookies_total=0,
            long_lived_cookie_count=0,
            samesite_none_sensitive_count=0,
            auth_cookie_missing_httponly_count=0,
            third_party_tracking_cookie_count=0,
            suspicious_signals=(),
        )

    uri = sqlite_ro_uri(cookies_path)
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=0.25, isolation_level=None)
    except sqlite3.Error as exc:
        return CookieAuditResult(
            opened_ro=False,
            parse_error=str(exc),
            cookies_total=0,
            long_lived_cookie_count=0,
            samesite_none_sensitive_count=0,
            auth_cookie_missing_httponly_count=0,
            third_party_tracking_cookie_count=0,
            suspicious_signals=(),
        )

    try:
        connection.execute("PRAGMA busy_timeout = 250;")
        connection.execute("PRAGMA query_only = ON;")
        connection.execute("PRAGMA temp_store = MEMORY;")
        cookies = _load_cookies(connection)
    except sqlite3.Error as exc:
        return CookieAuditResult(
            opened_ro=True,
            parse_error=str(exc),
            cookies_total=0,
            long_lived_cookie_count=0,
            samesite_none_sensitive_count=0,
            auth_cookie_missing_httponly_count=0,
            third_party_tracking_cookie_count=0,
            suspicious_signals=(),
        )
    finally:
        connection.close()

    reasons_by_cookie: dict[tuple[str, str], set[str]] = {}
    tracking_cookie_keys: set[tuple[str, str]] = set()
    long_lived_cookie_count = 0
    samesite_none_sensitive_count = 0
    auth_cookie_missing_httponly_count = 0
    third_party_tracking_cookie_count = 0

    for cookie in cookies:
        key = (cookie.host, cookie.name)

        if _is_long_lived(cookie):
            long_lived_cookie_count += 1
            reasons_by_cookie.setdefault(key, set()).add("long_lived_cookie")

        if _is_samesite_none(cookie.same_site) and _is_sensitive_domain(cookie.host):
            samesite_none_sensitive_count += 1
            reasons_by_cookie.setdefault(key, set()).add("samesite_none_sensitive_domain")

        if not cookie.is_http_only and _looks_like_auth_cookie(cookie.name):
            auth_cookie_missing_httponly_count += 1
            reasons_by_cookie.setdefault(key, set()).add("auth_cookie_missing_httponly")

        if _is_tracking_cookie_host(cookie.host):
            third_party_tracking_cookie_count += 1
            tracking_cookie_keys.add(key)

    if third_party_tracking_cookie_count > _TRACKING_COOKIE_EXCESS_THRESHOLD:
        for key in tracking_cookie_keys:
            reasons_by_cookie.setdefault(key, set()).add("third_party_tracking_cookie")

    suspicious_signals = tuple(
        CookieSecuritySignal(
            host=host,
            name=name,
            reasons=tuple(sorted(reason_set)),
        )
        for (host, name), reason_set in sorted(
            reasons_by_cookie.items(),
            key=lambda item: (item[0][0].lower(), item[0][1].lower()),
        )
    )
    return CookieAuditResult(
        opened_ro=True,
        parse_error=None,
        cookies_total=len(cookies),
        long_lived_cookie_count=long_lived_cookie_count,
        samesite_none_sensitive_count=samesite_none_sensitive_count,
        auth_cookie_missing_httponly_count=auth_cookie_missing_httponly_count,
        third_party_tracking_cookie_count=third_party_tracking_cookie_count,
        suspicious_signals=suspicious_signals,
    )


def _load_cookies(connection: sqlite3.Connection) -> tuple[CookieEntry, ...]:
    table_names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name ASC"
        )
    }
    if "moz_cookies" not in table_names:
        return ()

    columns = _table_columns(connection, "moz_cookies")
    if "host" not in columns or "name" not in columns:
        return ()

    query = "\n".join(
        [
            "SELECT",
            "  host,",
            "  name,",
            "  expiry" if "expiry" in columns else "  NULL AS expiry",
            ",",
            "  creationTime" if "creationTime" in columns else "  NULL AS creationTime",
            ",",
            "  isHttpOnly" if "isHttpOnly" in columns else "  NULL AS isHttpOnly",
            ",",
            "  sameSite" if "sameSite" in columns else "  NULL AS sameSite",
            "FROM moz_cookies",
            "ORDER BY lower(host) ASC, lower(name) ASC, rowid ASC",
        ]
    )
    rows = connection.execute(query).fetchall()
    entries: list[CookieEntry] = []
    for host_raw, name_raw, expiry_raw, creation_raw, httponly_raw, same_site_raw in rows:
        entries.append(
            CookieEntry(
                host=_normalize_host(_decode_db_text(host_raw)),
                name=_decode_db_text(name_raw).strip(),
                expiry_epoch=_decode_epoch_seconds(expiry_raw),
                creation_epoch=_decode_creation_epoch_seconds(creation_raw),
                is_http_only=_decode_bool_flag(httponly_raw),
                same_site=_normalize_same_site(same_site_raw),
            )
        )
    return tuple(entries)


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table_name});").fetchall()
    return {str(row[1]) for row in rows if len(row) > 1}


def _is_long_lived(cookie: CookieEntry) -> bool:
    if cookie.expiry_epoch is None or cookie.creation_epoch is None:
        return False
    return (cookie.expiry_epoch - cookie.creation_epoch) > _COOKIE_LIFETIME_THRESHOLD_SECONDS


def _is_samesite_none(same_site: str | None) -> bool:
    return same_site == "none"


def _is_sensitive_domain(host: str) -> bool:
    host_l = host.lower()
    if not host_l:
        return False
    return any(token in host_l for token in _SENSITIVE_DOMAIN_TOKENS)


def _looks_like_auth_cookie(name: str) -> bool:
    name_l = name.lower()
    if not name_l:
        return False
    if name_l in {"sid", "ssid", "sessionid"}:
        return True
    return _AUTH_COOKIE_NAME_RE.search(name_l) is not None


def _is_tracking_cookie_host(host: str) -> bool:
    if not host:
        return False
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in _TRACKER_HOST_SUFFIXES)


def _normalize_host(raw_host: str) -> str:
    host = raw_host.strip().lower()
    while host.startswith("."):
        host = host[1:]
    return host


def _normalize_same_site(raw_value: object) -> str | None:
    as_int = _decode_db_int(raw_value)
    if as_int is not None:
        if as_int == 0:
            return "none"
        if as_int == 1:
            return "lax"
        if as_int == 2:
            return "strict"
        return str(as_int)

    text = _decode_db_text(raw_value).strip().lower()
    if text in {"", "null"}:
        return None
    if text in {"none", "no_restriction", "no-restriction"}:
        return "none"
    if text == "lax":
        return "lax"
    if text == "strict":
        return "strict"
    return text


def _decode_bool_flag(raw_value: object) -> bool:
    as_int = _decode_db_int(raw_value)
    if as_int is not None:
        return as_int == 1
    text = _decode_db_text(raw_value).strip().lower()
    return text in {"1", "true", "yes", "on"}


def _decode_epoch_seconds(raw_value: object) -> int | None:
    as_int = _decode_db_int(raw_value)
    if as_int is None or as_int <= 0:
        return None
    return as_int


def _decode_creation_epoch_seconds(raw_value: object) -> int | None:
    as_int = _decode_db_int(raw_value)
    if as_int is None or as_int <= 0:
        return None
    if as_int > 10_000_000_000:
        return as_int // 1_000_000
    return as_int


def _decode_db_int(raw_value: object) -> int | None:
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        return int(raw_value)
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, float):
        return int(raw_value)
    if isinstance(raw_value, bytes):
        raw_value = raw_value.decode("utf-8", errors="replace")

    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return None
    return None


def _decode_db_text(raw_value: object) -> str:
    if raw_value is None:
        return ""
    if isinstance(raw_value, bytes):
        return raw_value.decode("utf-8", errors="replace")
    return str(raw_value)
