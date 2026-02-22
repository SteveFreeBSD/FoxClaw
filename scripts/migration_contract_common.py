#!/usr/bin/env python3
"""Shared helpers for WS-32 migration contract fixtures and verification."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTBED_ROOT = REPO_ROOT / "tests" / "fixtures" / "testbed"
TESTBED_RULESET = TESTBED_ROOT / "rulesets" / "integration.yml"
TESTBED_POLICY = TESTBED_ROOT / "policies" / "disable_telemetry.json"
MIGRATION_CONTRACT_FIXTURES_ROOT = REPO_ROOT / "tests" / "fixtures" / "migration_contracts"
REPO_ROOT_PLACEHOLDER = "<REPO_ROOT>"
CONTRACT_FIXTURE_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class ContractCase:
    name: str
    profile_name: str
    with_policy_path: bool
    expected_exit_code: int


CONTRACT_CASES: list[ContractCase] = [
    ContractCase("profile_baseline", "profile_baseline", False, 0),
    ContractCase("profile_weak_perms", "profile_weak_perms", False, 2),
    ContractCase("profile_sqlite_error", "profile_sqlite_error", False, 2),
    ContractCase("profile_policy_present", "profile_policy_present", True, 0),
    ContractCase("profile_userjs_override", "profile_userjs_override", True, 0),
    ContractCase("profile_third_party_xpi", "profile_third_party_xpi", False, 0),
]
CONTRACT_CASE_BY_NAME = {case.name: case for case in CONTRACT_CASES}

DEFAULT_PROFILE_FILE_MODE = 0o600
WEAK_PROFILE_FILE_MODE = 0o644


def normalize_contract_payload(payload: Any, *, repo_root: Path) -> Any:
    """Normalize host-specific paths in payloads for cross-host canonical fixtures."""
    if isinstance(payload, dict):
        normalized: dict[str, Any] = {}
        for key, value in payload.items():
            if key in {"owner_uid", "owner_gid"} and isinstance(value, int):
                normalized[key] = 0
                continue
            normalized[key] = normalize_contract_payload(value, repo_root=repo_root)
        return normalized
    if isinstance(payload, list):
        return [normalize_contract_payload(value, repo_root=repo_root) for value in payload]
    if isinstance(payload, str):
        return _normalize_contract_string(payload, repo_root=repo_root)
    return payload


def _normalize_contract_string(text: str, *, repo_root: Path) -> str:
    normalized = text
    repo_candidates = {
        repo_root.as_posix(),
        str(repo_root),
    }
    for candidate in repo_candidates:
        if candidate:
            normalized = normalized.replace(candidate, REPO_ROOT_PLACEHOLDER)
    return normalized


def stage_contract_case_profile(*, case: ContractCase, testbed_root: Path, work_root: Path) -> Path:
    """Copy a profile fixture and normalize file modes for deterministic case exits."""
    source = testbed_root / case.profile_name
    if not source.exists():
        raise FileNotFoundError(f"missing profile fixture: {source}")

    target = work_root / "profile"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)

    file_mode = WEAK_PROFILE_FILE_MODE if case.name == "profile_weak_perms" else DEFAULT_PROFILE_FILE_MODE
    for path in target.rglob("*"):
        if path.is_file():
            path.chmod(file_mode)
    return target
