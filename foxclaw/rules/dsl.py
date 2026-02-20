"""Rule DSL checks for finding evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from foxclaw.models import EvidenceBundle, FilePermEvidence

WELL_KNOWN_SENSITIVE_FILES: dict[str, str] = {
    "logins": "logins.json",
    "key4": "key4.db",
    "cert9": "cert9.db",
    "cookies": "cookies.sqlite",
    "places": "places.sqlite",
    "extensions": "extensions.json",
    "prefs": "prefs.js",
    "user": "user.js",
    "cookies_wal": "cookies.sqlite-wal",
    "cookies_shm": "cookies.sqlite-shm",
    "places_wal": "places.sqlite-wal",
    "places_shm": "places.sqlite-shm",
}

SQLITE_NAME_MAP: dict[str, str] = {
    "places": "places.sqlite",
    "cookies": "cookies.sqlite",
}
_RISK_LEVEL_ORDER = {"medium": 0, "high": 1}


@dataclass(slots=True)
class CheckResult:
    """Result for a single DSL rule check."""

    passed: bool
    evidence: list[str] = field(default_factory=list)


def evaluate_check(bundle: EvidenceBundle, check: dict[str, object]) -> CheckResult:
    """Evaluate a single check object from a rule definition."""
    if len(check) != 1:
        raise ValueError("rule check must contain exactly one DSL operator")

    check_name, config = next(iter(check.items()))
    if check_name == "pref_equals":
        return _check_pref_equals(bundle, _as_dict(config, check_name))
    if check_name == "pref_exists":
        return _check_pref_exists(bundle, _as_dict(config, check_name))
    if check_name == "file_perm_strict":
        return _check_file_perm_strict(bundle, _as_dict(config, check_name))
    if check_name == "policy_key_exists":
        return _check_policy_key_exists(bundle, config)
    if check_name == "sqlite_quickcheck_ok":
        return _check_sqlite_quickcheck_ok(bundle, config)
    if check_name == "extension_unsigned_absent":
        return _check_extension_unsigned_absent(bundle, config)
    if check_name == "extension_permission_risk_absent":
        return _check_extension_permission_risk_absent(bundle, config)
    if check_name == "extension_blocklisted_absent":
        return _check_extension_blocklisted_absent(bundle, config)
    raise ValueError(f"unsupported DSL check: {check_name}")


def _check_pref_equals(bundle: EvidenceBundle, config: dict[str, object]) -> CheckResult:
    key = _required_str(config, "key")
    if key not in bundle.prefs.root:
        # Unset prefs do not fail equality checks by default.
        return CheckResult(passed=True)

    expected = config.get("value")
    if not isinstance(expected, bool | int | str):
        raise ValueError("pref_equals value must be bool, int, or string")

    pref = bundle.prefs.root[key]
    if pref.value == expected:
        return CheckResult(passed=True)

    return CheckResult(
        passed=False,
        evidence=[
            f"{key}: expected={expected!r}, observed={pref.value!r}, source={pref.source}"
        ],
    )


def _check_pref_exists(bundle: EvidenceBundle, config: dict[str, object]) -> CheckResult:
    key = _required_str(config, "key")
    if key in bundle.prefs.root:
        pref = bundle.prefs.root[key]
        return CheckResult(
            passed=True,
            evidence=[f"{key}: present, source={pref.source}, type={pref.raw_type}"],
        )

    return CheckResult(passed=False, evidence=[f"{key}: unset"])


def _check_file_perm_strict(bundle: EvidenceBundle, config: dict[str, object]) -> CheckResult:
    path_glob = config.get("path_glob")
    key = config.get("key")

    if path_glob is None and key is None:
        raise ValueError("file_perm_strict requires either path_glob or key")

    matches = _match_file_evidence(bundle.filesystem, path_glob=path_glob, key=key)
    if not matches:
        # If the file is absent from evidence, this check is non-failing.
        return CheckResult(passed=True)

    violations = [
        item
        for item in matches
        if item.group_readable
        or item.group_writable
        or item.world_readable
        or item.world_writable
    ]
    if not violations:
        return CheckResult(passed=True)

    evidence = [
        (
            f"{item.path}: mode={item.mode} "
            f"group(r={int(item.group_readable)},w={int(item.group_writable)}) "
            f"world(r={int(item.world_readable)},w={int(item.world_writable)})"
        )
        for item in violations
    ]
    return CheckResult(passed=False, evidence=evidence)


def _check_policy_key_exists(bundle: EvidenceBundle, config: object) -> CheckResult:
    dotted = _extract_policy_path(config)

    for summary in bundle.policies.summaries:
        if summary.parse_error is not None:
            continue
        if dotted in summary.key_paths:
            return CheckResult(
                passed=True,
                evidence=[f"{dotted}: found in {summary.path}"],
            )
        if "." not in dotted and dotted in summary.top_level_keys:
            return CheckResult(
                passed=True,
                evidence=[f"{dotted}: found in {summary.path}"],
            )

    if not bundle.policies.summaries:
        return CheckResult(
            passed=False,
            evidence=[f"{dotted}: not found (no policies.json discovered)"],
        )
    return CheckResult(passed=False, evidence=[f"{dotted}: not found"])


def _check_sqlite_quickcheck_ok(bundle: EvidenceBundle, config: object) -> CheckResult:
    db_name = _extract_sqlite_db_name(config)
    sqlite_file = SQLITE_NAME_MAP[db_name]

    target = next(
        (
            item
            for item in bundle.sqlite.checks
            if Path(item.db_path).name == sqlite_file
        ),
        None,
    )
    if target is None:
        return CheckResult(
            passed=False,
            evidence=[f"{db_name}: no quick_check evidence for {sqlite_file}"],
        )

    quick_ok = target.quick_check_result.strip().lower() == "ok"
    if quick_ok and target.opened_ro:
        return CheckResult(
            passed=True,
            evidence=[f"{sqlite_file}: quick_check=ok, opened_ro=1"],
        )

    return CheckResult(
        passed=False,
        evidence=[
            (
                f"{sqlite_file}: quick_check={target.quick_check_result}, "
                f"opened_ro={int(target.opened_ro)}"
            )
        ],
    )


def _check_extension_unsigned_absent(bundle: EvidenceBundle, config: object) -> CheckResult:
    include_inactive, include_system = _extract_extension_scope_config(
        config, "extension_unsigned_absent"
    )
    candidates = [
        item
        for item in bundle.extensions.entries
        if (include_inactive or item.active is True)
        and (include_system or not _is_system_extension(item.source_kind))
    ]
    violations = [item for item in candidates if item.signed_valid is False]
    if not violations:
        return CheckResult(passed=True)

    evidence = [
        (
            f"{item.addon_id}: signed_valid=0, signed_state={item.signed_state or 'unknown'}, "
            f"active={int(item.active is True)}"
        )
        for item in violations
    ]
    return CheckResult(passed=False, evidence=evidence)


def _check_extension_blocklisted_absent(bundle: EvidenceBundle, config: object) -> CheckResult:
    include_inactive, include_system = _extract_extension_scope_config(
        config, "extension_blocklisted_absent"
    )
    candidates = [
        item
        for item in bundle.extensions.entries
        if (include_inactive or item.active is True)
        and (include_system or not _is_system_extension(item.source_kind))
    ]
    violations = [item for item in candidates if item.blocklisted is True]
    if not violations:
        return CheckResult(passed=True)

    evidence = [
        f"{item.addon_id}: blocklisted=1, active={int(item.active is True)}"
        for item in violations
    ]
    return CheckResult(passed=False, evidence=evidence)


def _check_extension_permission_risk_absent(
    bundle: EvidenceBundle, config: object
) -> CheckResult:
    min_level, include_inactive, include_system = _extract_extension_risk_config(config)
    candidates = [
        item
        for item in bundle.extensions.entries
        if (include_inactive or item.active is True)
        and (include_system or not _is_system_extension(item.source_kind))
    ]

    evidence: list[str] = []
    for item in candidates:
        for risk in item.risky_permissions:
            if _RISK_LEVEL_ORDER[risk.level] < _RISK_LEVEL_ORDER[min_level]:
                continue
            evidence.append(
                f"{item.addon_id}: permission={risk.permission}, "
                f"level={risk.level}, active={int(item.active is True)}"
            )

    if not evidence:
        return CheckResult(passed=True)
    return CheckResult(passed=False, evidence=sorted(evidence))


def _match_file_evidence(
    filesystem: list[FilePermEvidence], *, path_glob: object, key: object
) -> list[FilePermEvidence]:
    if path_glob is not None:
        glob_text = _require_value_type(path_glob, str, "path_glob")
        return [
            item
            for item in filesystem
            if fnmatch(item.path, glob_text) or fnmatch(Path(item.path).name, glob_text)
        ]

    key_text = _require_value_type(key, str, "key")
    expected_name = WELL_KNOWN_SENSITIVE_FILES.get(key_text)
    if expected_name is None:
        raise ValueError(f"unknown file_perm_strict key: {key_text}")

    return [item for item in filesystem if Path(item.path).name == expected_name]


def _extract_policy_path(config: object) -> str:
    if isinstance(config, str):
        dotted = config.strip()
    elif isinstance(config, dict):
        dotted = _required_str(config, "path")
    else:
        raise ValueError("policy_key_exists config must be string or object with path")

    if not dotted:
        raise ValueError("policy_key_exists path cannot be empty")
    return dotted


def _extract_sqlite_db_name(config: object) -> str:
    if isinstance(config, str):
        db_name = config.strip()
    elif isinstance(config, dict):
        db_name = _required_str(config, "db")
    else:
        raise ValueError("sqlite_quickcheck_ok config must be string or object with db")

    if db_name not in SQLITE_NAME_MAP:
        raise ValueError("sqlite_quickcheck_ok db must be one of: places, cookies")
    return db_name


def _extract_extension_scope_config(config: object, check_name: str) -> tuple[bool, bool]:
    if config is None:
        return False, False
    if not isinstance(config, dict):
        raise ValueError(f"{check_name} config must be an object when provided")

    include_inactive = config.get("include_inactive", False)
    if not isinstance(include_inactive, bool):
        raise ValueError(f"{check_name} include_inactive must be a boolean")

    include_system = config.get("include_system", False)
    if not isinstance(include_system, bool):
        raise ValueError(f"{check_name} include_system must be a boolean")
    return include_inactive, include_system


def _extract_extension_risk_config(config: object) -> tuple[str, bool, bool]:
    if config is None:
        return "high", False, False
    if not isinstance(config, dict):
        raise ValueError("extension_permission_risk_absent config must be an object")

    min_level_obj = config.get("min_level", "high")
    min_level = _require_value_type(min_level_obj, str, "min_level").lower()
    if min_level not in _RISK_LEVEL_ORDER:
        raise ValueError("extension_permission_risk_absent min_level must be high or medium")

    include_inactive_obj = config.get("include_inactive", False)
    if not isinstance(include_inactive_obj, bool):
        raise ValueError("extension_permission_risk_absent include_inactive must be a boolean")
    include_system_obj = config.get("include_system", False)
    if not isinstance(include_system_obj, bool):
        raise ValueError("extension_permission_risk_absent include_system must be a boolean")
    return min_level, include_inactive_obj, include_system_obj


def _is_system_extension(source_kind: str) -> bool:
    return source_kind in {"system", "builtin"}


def _as_dict(config: object, check_name: str) -> dict[str, object]:
    if not isinstance(config, dict):
        raise ValueError(f"{check_name} config must be an object")
    return config


def _required_str(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    return _require_value_type(value, str, key)


def _require_value_type(value: object, expected: type[str], field_name: str) -> str:
    if not isinstance(value, expected):
        raise ValueError(f"{field_name} must be a string")
    return value
