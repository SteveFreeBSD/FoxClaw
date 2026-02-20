"""Version parsing and range matching helpers for intel correlation."""

from __future__ import annotations

import re

_VERSION_PATTERN = re.compile(r"(\d+(?:\.\d+)*)")
_COMPARATOR_PATTERN = re.compile(r"^(<=|>=|<|>|==)\s*([^\s,]+)\s*$")


def normalize_version(raw: str) -> str | None:
    """Extract dotted numeric Firefox version prefix from arbitrary text."""
    match = _VERSION_PATTERN.search(raw)
    if match is None:
        return None
    normalized = match.group(1).strip(".")
    if not normalized:
        return None
    return normalized


def parse_version_tuple(raw: str) -> tuple[int, ...]:
    """Parse a dotted version string into comparable integer tuple."""
    normalized = normalize_version(raw)
    if normalized is None:
        raise ValueError(f"unable to parse version value '{raw}'")

    segments = normalized.split(".")
    numbers = [int(segment) for segment in segments if segment != ""]
    if not numbers:
        raise ValueError(f"unable to parse version value '{raw}'")

    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    return tuple(numbers)


def compare_versions(left: str, right: str) -> int:
    """Compare two Firefox versions; returns -1, 0, or 1."""
    left_tuple = parse_version_tuple(left)
    right_tuple = parse_version_tuple(right)
    max_len = max(len(left_tuple), len(right_tuple))
    padded_left = left_tuple + (0,) * (max_len - len(left_tuple))
    padded_right = right_tuple + (0,) * (max_len - len(right_tuple))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def validate_version_spec(spec: str) -> None:
    """Validate affected-version expression syntax."""
    _parse_spec(spec)


def version_matches_spec(*, version: str, spec: str) -> bool:
    """Return True when the version satisfies every comparator in `spec`."""
    comparators = _parse_spec(spec)
    for operator, boundary in comparators:
        comparison = compare_versions(version, boundary)
        if operator == "<" and not comparison < 0:
            return False
        if operator == "<=" and not comparison <= 0:
            return False
        if operator == ">" and not comparison > 0:
            return False
        if operator == ">=" and not comparison >= 0:
            return False
        if operator == "==" and not comparison == 0:
            return False
    return True


def _parse_spec(spec: str) -> list[tuple[str, str]]:
    tokens = [token.strip() for token in spec.split(",") if token.strip()]
    if not tokens:
        raise ValueError("affected_versions expression cannot be empty")

    parsed: list[tuple[str, str]] = []
    for token in tokens:
        match = _COMPARATOR_PATTERN.match(token)
        if match is None:
            raise ValueError(f"invalid affected_versions token '{token}'")
        operator, raw_boundary = match.group(1), match.group(2)
        normalized_boundary = normalize_version(raw_boundary)
        if normalized_boundary is None:
            raise ValueError(f"invalid affected_versions boundary '{raw_boundary}'")
        # Ensure this boundary can always be compared deterministically later.
        parse_version_tuple(normalized_boundary)
        parsed.append((operator, normalized_boundary))
    return parsed
