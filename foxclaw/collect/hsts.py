"""Read-only HSTS state integrity audit helpers (WS-53)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from foxclaw.collect.safe_paths import (
    UnsafeProfilePathError,
    resolve_safe_profile_path,
    sqlite_ro_uri,
)

_CRITICAL_DOMAIN_SUFFIXES: tuple[str, ...] = (
    # banking
    "americanexpress.com",
    "bankofamerica.com",
    "capitalone.com",
    "chase.com",
    "citi.com",
    "paypal.com",
    "wellsfargo.com",
    # email
    "gmail.com",
    "icloud.com",
    "outlook.com",
    "outlook.live.com",
    "proton.me",
    "yahoo.com",
    # corporate identity / SSO
    "duosecurity.com",
    "microsoftonline.com",
    "okta.com",
    "onelogin.com",
)


@dataclass(frozen=True, slots=True)
class HstsEntry:
    """One parsed HSTS entry."""

    host: str
    include_subdomains: bool


@dataclass(frozen=True, slots=True)
class HstsRisk:
    """One suspicious HSTS integrity signal."""

    host: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HstsAuditResult:
    """Deterministic SiteSecurityServiceState.txt audit output."""

    parse_error: str | None
    entries: tuple[HstsEntry, ...]
    critical_hosts_expected: tuple[str, ...]
    missing_critical_hosts: tuple[str, ...]
    malformed_line_count: int
    suspicious_signals: tuple[HstsRisk, ...]


def audit_hsts_state(path: Path) -> HstsAuditResult:
    """Audit HSTS state for downgrade/removal patterns on critical domains."""
    if not path.is_file():
        return HstsAuditResult(
            parse_error=None,
            entries=(),
            critical_hosts_expected=(),
            missing_critical_hosts=(),
            malformed_line_count=0,
            suspicious_signals=(),
        )

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return HstsAuditResult(
            parse_error=str(exc),
            entries=(),
            critical_hosts_expected=(),
            missing_critical_hosts=(),
            malformed_line_count=0,
            suspicious_signals=(),
        )

    entries, malformed_line_count = _parse_hsts_entries(text)
    critical_hosts_expected = _load_critical_https_hosts(path.parent)
    missing_critical_hosts = tuple(
        host
        for host in critical_hosts_expected
        if not _is_hsts_covered(host=host, entries=entries)
    )

    reasons_by_host: dict[str, set[str]] = {}
    for host in missing_critical_hosts:
        reasons_by_host.setdefault(host, set()).add("missing_critical_hsts_entry")
        host_base = _registrable_domain(host)
        if any(_registrable_domain(entry.host) == host_base for entry in entries):
            reasons_by_host.setdefault(host, set()).add("selective_hsts_entry_deletion")

    if missing_critical_hosts and _looks_truncated(
        text=text,
        entries=entries,
        expected_count=len(critical_hosts_expected),
        malformed_line_count=malformed_line_count,
    ):
        reasons_by_host.setdefault("<global>", set()).add("hsts_file_truncation_pattern")

    suspicious_signals = tuple(
        HstsRisk(host=host, reasons=tuple(sorted(reasons)))
        for host, reasons in sorted(reasons_by_host.items(), key=lambda item: item[0].lower())
    )
    return HstsAuditResult(
        parse_error=None,
        entries=entries,
        critical_hosts_expected=critical_hosts_expected,
        missing_critical_hosts=missing_critical_hosts,
        malformed_line_count=malformed_line_count,
        suspicious_signals=suspicious_signals,
    )


def _parse_hsts_entries(text: str) -> tuple[tuple[HstsEntry, ...], int]:
    rows: dict[str, bool] = {}
    malformed_line_count = 0

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("\t")
        if len(parts) < 2:
            malformed_line_count += 1
            continue

        host = _parse_host(parts[0])
        if not host:
            malformed_line_count += 1
            continue

        state = parts[1].strip().upper()
        if state != "HSTS":
            continue

        include_subdomains = _parse_bool(parts[5]) if len(parts) > 5 else False
        previous = rows.get(host)
        rows[host] = include_subdomains if previous is None else (previous or include_subdomains)

    entries = tuple(
        HstsEntry(host=host, include_subdomains=include_subdomains)
        for host, include_subdomains in sorted(rows.items(), key=lambda item: item[0].lower())
    )
    return entries, malformed_line_count


def _parse_host(raw_host: str) -> str:
    host_port = raw_host.strip().lower()
    if not host_port:
        return ""

    if host_port.startswith("[") and "]" in host_port:
        host = host_port.split("]", 1)[0].lstrip("[")
    elif ":" in host_port:
        candidate, maybe_port = host_port.rsplit(":", 1)
        host = candidate if maybe_port.isdigit() else host_port
    else:
        host = host_port

    host = host.strip().strip(".")
    return host


def _parse_bool(raw_value: object) -> bool:
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, int):
        return raw_value == 1
    text = str(raw_value).strip().lower()
    return text in {"1", "true", "yes", "on"}


def _is_hsts_covered(host: str, entries: tuple[HstsEntry, ...]) -> bool:
    for entry in entries:
        if host == entry.host:
            return True
        if entry.include_subdomains and host.endswith(f".{entry.host}"):
            return True
    return False


def _looks_truncated(
    *, text: str, entries: tuple[HstsEntry, ...], expected_count: int, malformed_line_count: int
) -> bool:
    if expected_count <= 0:
        return False
    if not entries:
        return True
    if malformed_line_count > 0 and len(entries) <= 1:
        return True
    if expected_count >= 3 and (len(entries) * 2) < expected_count:
        return True
    if text and not text.endswith("\n"):
        return True
    return False


def _load_critical_https_hosts(profile_dir: Path) -> tuple[str, ...]:
    try:
        places_path = resolve_safe_profile_path(profile_dir, "places.sqlite")
    except UnsafeProfilePathError:
        return ()
    if not places_path.is_file():
        return ()

    uri = sqlite_ro_uri(places_path)
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=0.25, isolation_level=None)
    except sqlite3.Error:
        return ()

    try:
        connection.execute("PRAGMA busy_timeout = 250;")
        connection.execute("PRAGMA query_only = ON;")
        connection.execute("PRAGMA temp_store = MEMORY;")
        rows = connection.execute("SELECT url FROM moz_places ORDER BY id ASC").fetchall()
    except sqlite3.Error:
        return ()
    finally:
        connection.close()

    hosts: set[str] = set()
    for row in rows:
        if not row:
            continue
        url = row[0]
        if not isinstance(url, str):
            continue
        parts = urlsplit(url)
        if parts.scheme.lower() != "https":
            continue
        if not parts.hostname:
            continue
        host = parts.hostname.strip().lower().strip(".")
        if _is_critical_domain(host):
            hosts.add(host)
    return tuple(sorted(hosts))


def _is_critical_domain(host: str) -> bool:
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in _CRITICAL_DOMAIN_SUFFIXES)


def _registrable_domain(host: str) -> str:
    tokens = [token for token in host.lower().split(".") if token]
    if len(tokens) >= 2:
        return ".".join(tokens[-2:])
    return host.lower()
