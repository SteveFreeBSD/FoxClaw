"""Read-only session restore data exposure audit helpers (WS-50)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_MOZ_LZ4_HEADER = b"mozLz40\x00"
_PASSWORD_KEY_RE = re.compile(r"(?i)pass(word)?|pwd")
_TOKEN_KEY_RE = re.compile(r"(?i)token|auth|session(_?id)?|jwt|bearer|csrf")
_CREDIT_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


@dataclass(frozen=True, slots=True)
class SessionSensitiveEntry:
    """One sensitive value indicator discovered in session restore data."""

    path: str
    kind: str


@dataclass(frozen=True, slots=True)
class SessionAuditResult:
    """Deterministic sessionstore.jsonlz4 audit output."""

    parse_error: str | None
    session_restore_enabled: bool
    windows_count: int
    sensitive_entries: tuple[SessionSensitiveEntry, ...]


def audit_sessionstore(path: Path) -> SessionAuditResult:
    """Audit sessionstore payload for sensitive data exposure indicators."""
    if not path.is_file():
        return SessionAuditResult(
            parse_error=None,
            session_restore_enabled=False,
            windows_count=0,
            sensitive_entries=(),
        )

    try:
        raw = path.read_bytes()
    except OSError as exc:
        return SessionAuditResult(
            parse_error=str(exc),
            session_restore_enabled=False,
            windows_count=0,
            sensitive_entries=(),
        )

    payload, parse_error = _decode_sessionstore_payload(raw)
    if parse_error is not None:
        return SessionAuditResult(
            parse_error=parse_error,
            session_restore_enabled=False,
            windows_count=0,
            sensitive_entries=(),
        )

    windows_obj = payload.get("windows")
    windows_count = len(windows_obj) if isinstance(windows_obj, list) else 0
    session_restore_enabled = windows_count > 0
    sensitive_entries = _collect_sensitive_entries(payload)
    return SessionAuditResult(
        parse_error=None,
        session_restore_enabled=session_restore_enabled,
        windows_count=windows_count,
        sensitive_entries=sensitive_entries,
    )


def _decode_sessionstore_payload(raw: bytes) -> tuple[dict[str, Any], str | None]:
    if raw.startswith(_MOZ_LZ4_HEADER):
        body = raw[len(_MOZ_LZ4_HEADER) :]
        return _decode_json_body(body, prefer_lz4_decompress=True)
    return _decode_json_body(raw, prefer_lz4_decompress=False)


def _decode_json_body(body: bytes, *, prefer_lz4_decompress: bool) -> tuple[dict[str, Any], str | None]:
    if not body:
        return {}, None

    parse_candidates: list[bytes] = [body]
    if prefer_lz4_decompress:
        decompressed = _try_lz4_decompress(body)
        if decompressed is not None and decompressed != body:
            parse_candidates.append(decompressed)

    for candidate in parse_candidates:
        try:
            payload = json.loads(candidate.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload, None
        return {}, "sessionstore payload top-level JSON is not an object"

    if prefer_lz4_decompress and _try_lz4_decompress(body) is None:
        return {}, "unable to decode compressed sessionstore payload (lz4.block unavailable)"
    return {}, "unable to decode sessionstore payload as JSON"


def _try_lz4_decompress(data: bytes) -> bytes | None:
    try:
        import lz4.block  # type: ignore[import-not-found]
    except ImportError:
        return None

    try:
        result = lz4.block.decompress(data)
    except Exception:
        return None
    return result if isinstance(result, bytes) else None


def _collect_sensitive_entries(payload: dict[str, Any]) -> tuple[SessionSensitiveEntry, ...]:
    found: set[tuple[str, str]] = set()
    for path, key, value in _walk_scalars(payload):
        value_text = value.strip()
        if not value_text:
            continue

        key_lower = key.lower()
        if _PASSWORD_KEY_RE.search(key_lower):
            found.add((path, "password_field"))
        if _TOKEN_KEY_RE.search(key_lower):
            found.add((path, "auth_token_field"))
        if _contains_credit_card_number(value_text):
            found.add((path, "credit_card_pattern"))

    return tuple(
        SessionSensitiveEntry(path=item[0], kind=item[1])
        for item in sorted(found, key=lambda pair: (pair[0], pair[1]))
    )


def _walk_scalars(
    value: Any, *, current_path: str = "$", current_key: str = ""
) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []

    if isinstance(value, dict):
        for key in sorted(value):
            next_value = value[key]
            next_path = f"{current_path}.{key}" if current_path else str(key)
            rows.extend(_walk_scalars(next_value, current_path=next_path, current_key=str(key)))
        return rows

    if isinstance(value, list):
        for idx, item in enumerate(value):
            next_path = f"{current_path}[{idx}]"
            rows.extend(_walk_scalars(item, current_path=next_path, current_key=current_key))
        return rows

    if isinstance(value, str):
        rows.append((current_path, current_key, value))
    return rows


def _contains_credit_card_number(text: str) -> bool:
    for match in _CREDIT_CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _passes_luhn(digits):
            return True
    return False


def _passes_luhn(number: str) -> bool:
    total = 0
    reverse_digits = number[::-1]
    for idx, char in enumerate(reverse_digits):
        digit = int(char)
        if idx % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0
