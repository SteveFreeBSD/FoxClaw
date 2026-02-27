"""Protocol handler hijack detection helpers for handlers.json (WS-47)."""

from __future__ import annotations

from dataclasses import dataclass
import re

_EXECUTABLE_SUFFIX_RE = re.compile(
    r"(?i)(?:\.exe|\.bat|\.ps1|\.cmd|\.sh)(?=$|\s|['\"])"
)
_REMOTE_URI_SCHEME_RE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://")
_WINDOWS_DRIVE_RE = re.compile(r"(?i)^[a-z]:[\\/]")


@dataclass(frozen=True, slots=True)
class ProtocolHandlerRisk:
    """One suspicious custom protocol handler binding."""

    scheme: str
    handler_path: str


def collect_protocol_handler_hijacks(payload: dict[str, object]) -> list[ProtocolHandlerRisk]:
    """Return deterministic suspicious protocol handlers from handlers.json payload."""
    schemes_obj = payload.get("schemes")
    if not isinstance(schemes_obj, dict):
        return []

    risks: list[ProtocolHandlerRisk] = []
    for scheme, scheme_payload in sorted(
        schemes_obj.items(),
        key=lambda item: str(item[0]).lower(),
    ):
        if not isinstance(scheme_payload, dict):
            continue
        if scheme_payload.get("ask") is not False:
            continue

        handlers_obj = scheme_payload.get("handlers")
        if not isinstance(handlers_obj, list):
            continue

        for handler in handlers_obj:
            if not isinstance(handler, dict):
                continue
            path_obj = handler.get("path")
            if not isinstance(path_obj, str):
                continue
            handler_path = path_obj.strip()
            if not _is_local_executable_path(handler_path):
                continue
            risks.append(ProtocolHandlerRisk(scheme=str(scheme), handler_path=handler_path))

    risks.sort(key=lambda item: (item.scheme.lower(), item.handler_path.lower()))
    return risks


def _is_local_executable_path(path: str) -> bool:
    if not path or _EXECUTABLE_SUFFIX_RE.search(path) is None:
        return False

    lowered = path.lower()
    if lowered.startswith("file://"):
        return True
    if _WINDOWS_DRIVE_RE.match(path):
        return True
    if path.startswith("\\\\"):
        return True
    if path.startswith("/"):
        return True
    if path.startswith("./") or path.startswith("../") or path.startswith("~"):
        return True

    # Relative/bare executable names are considered local execution targets.
    return _REMOTE_URI_SCHEME_RE.match(path) is None
