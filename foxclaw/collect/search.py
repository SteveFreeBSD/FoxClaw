"""Read-only search engine integrity audit helpers (WS-51)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_MOZ_LZ4_HEADER = b"mozLz40\x00"
_ALLOWED_ENGINE_NAMES: set[str] = {
    "google",
    "bing",
    "duckduckgo",
    "yahoo",
    "startpage",
    "qwant",
    "ecosia",
    "brave",
}
_ALLOWED_SEARCH_HOSTS: tuple[str, ...] = (
    "google.com",
    "google.co.uk",
    "google.ca",
    "bing.com",
    "duckduckgo.com",
    "search.yahoo.com",
    "startpage.com",
    "qwant.com",
    "ecosia.org",
    "search.brave.com",
)
_SEARCH_URL_KEY_RE = re.compile(r"(?i)url|template|search")


@dataclass(frozen=True, slots=True)
class SearchEngineEntry:
    """One parsed search engine entry."""

    name: str
    search_url: str
    is_default: bool


@dataclass(frozen=True, slots=True)
class SearchEngineRisk:
    """One suspicious default-search integrity signal."""

    name: str
    search_url: str
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SearchAuditResult:
    """Deterministic search.json.mozlz4 audit output."""

    parse_error: str | None
    engines: tuple[SearchEngineEntry, ...]
    default_engine_name: str | None
    default_engine_url: str | None
    suspicious_defaults: tuple[SearchEngineRisk, ...]


def audit_search_json(path: Path) -> SearchAuditResult:
    """Audit search engine defaults for hijack-like integrity issues."""
    if not path.is_file():
        return SearchAuditResult(
            parse_error=None,
            engines=(),
            default_engine_name=None,
            default_engine_url=None,
            suspicious_defaults=(),
        )

    try:
        raw = path.read_bytes()
    except OSError as exc:
        return SearchAuditResult(
            parse_error=str(exc),
            engines=(),
            default_engine_name=None,
            default_engine_url=None,
            suspicious_defaults=(),
        )

    payload, parse_error = _decode_payload(raw)
    if parse_error is not None:
        return SearchAuditResult(
            parse_error=parse_error,
            engines=(),
            default_engine_name=None,
            default_engine_url=None,
            suspicious_defaults=(),
        )

    engines = _extract_engines(payload)
    default_name, default_url = _resolve_default_engine(payload, engines)
    suspicious_defaults = _classify_default(default_name, default_url)
    return SearchAuditResult(
        parse_error=None,
        engines=engines,
        default_engine_name=default_name,
        default_engine_url=default_url,
        suspicious_defaults=suspicious_defaults,
    )


def _decode_payload(raw: bytes) -> tuple[dict[str, Any], str | None]:
    if raw.startswith(_MOZ_LZ4_HEADER):
        body = raw[len(_MOZ_LZ4_HEADER) :]
        return _decode_json_body(body, prefer_lz4_decompress=True)
    return _decode_json_body(raw, prefer_lz4_decompress=False)


def _decode_json_body(body: bytes, *, prefer_lz4_decompress: bool) -> tuple[dict[str, Any], str | None]:
    if not body:
        return {}, None

    candidates: list[bytes] = [body]
    if prefer_lz4_decompress:
        decompressed = _try_lz4_decompress(body)
        if decompressed is not None and decompressed != body:
            candidates.append(decompressed)

    for candidate in candidates:
        try:
            payload = json.loads(candidate.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload, None
        return {}, "search payload top-level JSON is not an object"

    if prefer_lz4_decompress and _try_lz4_decompress(body) is None:
        return {}, "unable to decode compressed search payload (lz4.block unavailable)"
    return {}, "unable to decode search payload as JSON"


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


def _extract_engines(payload: dict[str, Any]) -> tuple[SearchEngineEntry, ...]:
    engines_obj = payload.get("engines")
    if not isinstance(engines_obj, list):
        return ()

    rows: list[SearchEngineEntry] = []
    for entry in engines_obj:
        if not isinstance(entry, dict):
            continue

        name = _extract_engine_name(entry)
        search_url = _extract_engine_url(entry)
        is_default = bool(entry.get("isDefault") or entry.get("_isDefault"))
        rows.append(SearchEngineEntry(name=name, search_url=search_url, is_default=is_default))

    return tuple(sorted(rows, key=lambda item: (item.name.lower(), item.search_url.lower())))


def _extract_engine_name(entry: dict[str, Any]) -> str:
    for key in ("name", "_name", "identifier", "id", "engineName"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _extract_engine_url(entry: dict[str, Any]) -> str:
    for key, value in entry.items():
        if not isinstance(value, str):
            continue
        if _SEARCH_URL_KEY_RE.search(key) and value.strip():
            return value.strip()

    urls_obj = entry.get("urls")
    if isinstance(urls_obj, list):
        for item in urls_obj:
            if not isinstance(item, dict):
                continue
            for key in ("template", "searchUrl", "url"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def _resolve_default_engine(
    payload: dict[str, Any], engines: tuple[SearchEngineEntry, ...]
) -> tuple[str | None, str | None]:
    meta = payload.get("metaData")
    default_name: str | None = None

    if isinstance(meta, dict):
        for key in ("current", "currentEngine", "defaultEngine", "defaultEngineName", "selectedEngine"):
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                default_name = value.strip()
                break
            if isinstance(value, dict):
                nested_name = _extract_engine_name(value)
                if nested_name:
                    default_name = nested_name
                    break

    if default_name is None:
        explicit_default = next((item for item in engines if item.is_default), None)
        if explicit_default is not None:
            return explicit_default.name or None, explicit_default.search_url or None
        return None, None

    matched = next((item for item in engines if item.name == default_name), None)
    if matched is not None:
        return matched.name or None, matched.search_url or None
    return default_name, None


def _classify_default(name: str | None, url: str | None) -> tuple[SearchEngineRisk, ...]:
    if not name and not url:
        return ()

    reasons: list[str] = []
    normalized_name = (name or "").strip().lower()
    if normalized_name and normalized_name not in _ALLOWED_ENGINE_NAMES:
        reasons.append("non_standard_default_engine")

    normalized_url = (url or "").strip()
    if normalized_url:
        host = urlsplit(normalized_url).hostname
        host_l = host.lower() if host else ""
        if not host_l:
            reasons.append("custom_search_url")
        elif not any(host_l == allowed or host_l.endswith(f".{allowed}") for allowed in _ALLOWED_SEARCH_HOSTS):
            reasons.append("custom_search_url")

    if not reasons:
        return ()
    return (
        SearchEngineRisk(
            name=name or "",
            search_url=url or "",
            reasons=tuple(sorted(set(reasons))),
        ),
    )
