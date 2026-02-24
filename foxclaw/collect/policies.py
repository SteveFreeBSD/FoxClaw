"""Read-only collector for Firefox enterprise policy files."""

from __future__ import annotations

import json
from pathlib import Path

from foxclaw.collect.safe_paths import ProfilePathSymlinkError
from foxclaw.models import PolicyEvidence, PolicyFileSummary

DEFAULT_POLICY_PATHS: tuple[Path, ...] = (
    Path("/etc/firefox/policies/policies.json"),
    Path("/usr/lib/firefox/distribution/policies.json"),
    Path("/usr/lib64/firefox/distribution/policies.json"),
)


def collect_policies(policy_paths: list[Path] | None = None) -> PolicyEvidence:
    """Discover and summarize available `policies.json` files."""
    search_paths = policy_paths if policy_paths is not None else list(DEFAULT_POLICY_PATHS)
    discovered: list[Path] = []
    summaries: list[PolicyFileSummary] = []

    for policy_path in sorted(search_paths, key=lambda path: str(path)):
        if not policy_path.is_file():
            continue

        _reject_symlink_path(policy_path)
        discovered.append(policy_path)
        summaries.append(_summarize_policy_file(policy_path))

    return PolicyEvidence(
        searched_paths=[str(path) for path in search_paths],
        discovered_paths=[str(path) for path in discovered],
        summaries=summaries,
    )


def _summarize_policy_file(policy_path: Path) -> PolicyFileSummary:
    try:
        raw_text = policy_path.read_text(encoding="utf-8", errors="replace")
        payload = json.loads(raw_text)
    except (OSError, json.JSONDecodeError) as exc:
        return PolicyFileSummary(path=str(policy_path), parse_error=str(exc))

    if not isinstance(payload, dict):
        return PolicyFileSummary(path=str(policy_path), parse_error="top-level JSON is not an object")

    top_level_keys = sorted(str(key) for key in payload.keys())
    policies_count: int | None = None
    policies_obj = payload.get("policies")
    if isinstance(policies_obj, (dict, list)):
        policies_count = len(policies_obj)

    return PolicyFileSummary(
        path=str(policy_path),
        top_level_keys=top_level_keys,
        key_paths=_collect_key_paths(payload),
        policies_count=policies_count,
    )


def _collect_key_paths(payload: dict[str, object]) -> list[str]:
    key_paths: set[str] = set()

    def _walk(obj: object, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_text = str(key)
                current = f"{prefix}.{key_text}" if prefix else key_text
                key_paths.add(current)
                _walk(value, current)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, prefix)

    _walk(payload)
    return sorted(key_paths)


def _reject_symlink_path(policy_path: Path) -> None:
    expanded = policy_path.expanduser()
    if expanded.is_absolute():
        current = Path(expanded.anchor)
        parts = expanded.parts[1:]
    else:
        current = Path.cwd()
        parts = expanded.parts

    for token in parts:
        current = current / token
        if current.is_symlink():
            raise ProfilePathSymlinkError(f"symlinked profile path is not allowed: {current}")
