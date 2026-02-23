"""Read-only collector for Firefox preference files."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Literal

from foxclaw.collect.safe_paths import iter_safe_profile_files
from foxclaw.models import PrefEvidence, PrefRawType, PrefValue

_USER_PREF_RE = re.compile(
    r'^user_pref\(\s*"(?P<key>(?:\\.|[^"\\])*)"\s*,\s*(?P<value>.+?)\s*\)\s*;?\s*$'
)


def collect_prefs(profile_dir: Path) -> PrefEvidence:
    """Parse prefs.js and user.js with user.js precedence."""
    merged: dict[str, PrefValue] = {}
    for rel_path, file_path in iter_safe_profile_files(profile_dir, ("prefs.js", "user.js")):
        if rel_path == "prefs.js":
            merged.update(_parse_pref_file(file_path, source="prefs.js"))
            continue
        if rel_path == "user.js":
            merged.update(_parse_pref_file(file_path, source="user.js"))
    return PrefEvidence(root=dict(sorted(merged.items(), key=lambda item: item[0])))


def _parse_pref_file(
    profile_file: Path, *, source: Literal["prefs.js", "user.js"]
) -> dict[str, PrefValue]:
    if not profile_file.is_file():
        return {}

    parsed: dict[str, PrefValue] = {}
    try:
        content = profile_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    for raw_line in content.splitlines():
        parsed_item = _parse_pref_line(raw_line, source=source)
        if parsed_item is None:
            continue
        key, value = parsed_item
        parsed[key] = value
    return parsed


def _parse_pref_line(
    line: str, *, source: Literal["prefs.js", "user.js"]
) -> tuple[str, PrefValue] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("//") or stripped.startswith("#"):
        return None

    match = _USER_PREF_RE.match(stripped)
    if match is None:
        return None

    try:
        key = _decode_js_string(match.group("key"))
    except (SyntaxError, ValueError):
        return None
    parsed_value = _parse_pref_value(match.group("value"))
    if parsed_value is None:
        return None
    value, raw_type = parsed_value
    return key, PrefValue(value=value, source=source, raw_type=raw_type)


def _decode_js_string(raw: str) -> str:
    # Firefox pref keys are JS string literals; `ast.literal_eval` safely decodes escapes.
    decoded = ast.literal_eval(f'"{raw}"')
    if not isinstance(decoded, str):
        raise ValueError("decoded pref key is not a string")
    return decoded


def _parse_pref_value(value_text: str) -> tuple[bool | int | str, PrefRawType] | None:
    value_str = value_text.strip()
    if value_str == "true":
        return True, "bool"
    if value_str == "false":
        return False, "bool"
    if re.fullmatch(r"-?[0-9]+", value_str):
        try:
            return int(value_str), "int"
        except ValueError:
            return None
    if len(value_str) >= 2 and value_str[0] == '"' and value_str[-1] == '"':
        try:
            parsed = ast.literal_eval(value_str)
        except (SyntaxError, ValueError):
            return None
        if isinstance(parsed, str):
            return parsed, "string"
    return None
