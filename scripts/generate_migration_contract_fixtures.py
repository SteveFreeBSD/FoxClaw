#!/usr/bin/env python3
"""Generate or verify canonical WS-32 migration contract fixtures."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import shlex
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from migration_contract_common import (  # noqa: E402
    CONTRACT_CASE_BY_NAME,
    CONTRACT_CASES,
    CONTRACT_FIXTURE_SCHEMA_VERSION,
    MIGRATION_CONTRACT_FIXTURES_ROOT,
    REPO_ROOT,
    REPO_ROOT_PLACEHOLDER,
    TESTBED_POLICY,
    TESTBED_ROOT,
    TESTBED_RULESET,
    ContractCase,
    normalize_contract_payload,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="Write canonical fixtures")
    mode.add_argument("--check", action="store_true", help="Check canonical fixtures for drift")

    parser.add_argument(
        "--python-cmd",
        default=".venv/bin/python -m foxclaw",
        help="Engine command used to generate fixture outputs",
    )
    parser.add_argument(
        "--fixtures-root",
        type=Path,
        default=MIGRATION_CONTRACT_FIXTURES_ROOT,
        help="Root directory for migration contract fixtures",
    )
    parser.add_argument(
        "--testbed-root",
        type=Path,
        default=TESTBED_ROOT,
        help="Path to deterministic testbed root",
    )
    parser.add_argument(
        "--ruleset",
        type=Path,
        default=TESTBED_RULESET,
        help="Path to testbed integration ruleset",
    )
    parser.add_argument(
        "--policy-path",
        type=Path,
        default=TESTBED_POLICY,
        help="Path to deterministic policy fixture",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=sorted(CONTRACT_CASE_BY_NAME),
        default=[],
        help="Generate/check only selected scenario(s); repeatable",
    )
    return parser.parse_args()


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _sha256_text(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _build_scan_cmd(
    *,
    base_cmd: list[str],
    case: ContractCase,
    testbed_root: Path,
    ruleset: Path,
    policy_path: Path,
    json_out: Path,
    sarif_out: Path,
) -> list[str]:
    cmd = [
        *base_cmd,
        "scan",
        "--profile",
        str(testbed_root / case.profile_name),
        "--ruleset",
        str(ruleset),
        "--deterministic",
        "--output",
        str(json_out),
        "--sarif-out",
        str(sarif_out),
    ]
    if case.with_policy_path:
        cmd.extend(["--policy-path", str(policy_path)])
    return cmd


def _run_case(
    *,
    base_cmd: list[str],
    case: ContractCase,
    testbed_root: Path,
    ruleset: Path,
    policy_path: Path,
    workdir: Path,
) -> tuple[int, object, object]:
    case_dir = workdir / case.name
    case_dir.mkdir(parents=True, exist_ok=True)
    json_out = case_dir / "scan.json"
    sarif_out = case_dir / "scan.sarif"
    cmd = _build_scan_cmd(
        base_cmd=base_cmd,
        case=case,
        testbed_root=testbed_root,
        ruleset=ruleset,
        policy_path=policy_path,
        json_out=json_out,
        sarif_out=sarif_out,
    )
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    try:
        json_payload = json.loads(json_out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"error: failed to parse JSON output for case {case.name}: {exc}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        ) from exc
    try:
        sarif_payload = json.loads(sarif_out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"error: failed to parse SARIF output for case {case.name}: {exc}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        ) from exc
    return proc.returncode, json_payload, sarif_payload


def _build_expected_files(
    *,
    base_cmd: list[str],
    selected_cases: list[ContractCase],
    testbed_root: Path,
    ruleset: Path,
    policy_path: Path,
) -> dict[str, str]:
    expected_files: dict[str, str] = {}
    case_manifest: list[dict[str, object]] = []
    observed_json_schema_versions: set[str] = set()
    observed_sarif_versions: set[str] = set()

    with tempfile.TemporaryDirectory(prefix="foxclaw-migration-contract-gen-") as tmp_dir:
        tmp_root = Path(tmp_dir)
        for case in selected_cases:
            exit_code, json_payload, sarif_payload = _run_case(
                base_cmd=base_cmd,
                case=case,
                testbed_root=testbed_root,
                ruleset=ruleset,
                policy_path=policy_path,
                workdir=tmp_root,
            )
            if exit_code != case.expected_exit_code:
                raise SystemExit(
                    f"error: case {case.name} exit-code drift: expected={case.expected_exit_code} got={exit_code}"
                )

            normalized_json = normalize_contract_payload(json_payload, repo_root=REPO_ROOT)
            normalized_sarif = normalize_contract_payload(sarif_payload, repo_root=REPO_ROOT)

            json_text = _canonical_json(normalized_json)
            sarif_text = _canonical_json(normalized_sarif)

            json_rel = f"cases/{case.name}/scan.json"
            sarif_rel = f"cases/{case.name}/scan.sarif"
            expected_files[json_rel] = json_text
            expected_files[sarif_rel] = sarif_text

            observed_json_schema_versions.add(str(normalized_json.get("schema_version", "")))
            observed_sarif_versions.add(str(normalized_sarif.get("version", "")))

            case_manifest.append(
                {
                    "case": asdict(case),
                    "artifacts": {
                        "scan_json": json_rel,
                        "scan_json_sha256": _sha256_text(json_text),
                        "scan_sarif": sarif_rel,
                        "scan_sarif_sha256": _sha256_text(sarif_text),
                    },
                }
            )

    if len(observed_json_schema_versions) != 1:
        raise SystemExit(
            f"error: expected one scan schema_version, observed: {sorted(observed_json_schema_versions)}"
        )
    if len(observed_sarif_versions) != 1:
        raise SystemExit(
            f"error: expected one SARIF version, observed: {sorted(observed_sarif_versions)}"
        )

    manifest = {
        "contract_fixture_schema_version": CONTRACT_FIXTURE_SCHEMA_VERSION,
        "scan_schema_version": next(iter(observed_json_schema_versions)),
        "sarif_version": next(iter(observed_sarif_versions)),
        "repo_root_placeholder": REPO_ROOT_PLACEHOLDER,
        "cases_total": len(case_manifest),
        "cases": case_manifest,
    }
    expected_files["manifest.json"] = _canonical_json(manifest)
    return expected_files


def _write_expected_files(fixtures_root: Path, expected_files: dict[str, str]) -> None:
    fixtures_root.mkdir(parents=True, exist_ok=True)
    expected_paths: set[Path] = set()
    for relpath, payload in expected_files.items():
        path = fixtures_root / relpath
        expected_paths.add(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload + "\n", encoding="utf-8")

    all_existing = sorted(path for path in fixtures_root.rglob("*") if path.is_file())
    for path in all_existing:
        if path not in expected_paths:
            path.unlink()

    for path in sorted(fixtures_root.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()


def _check_expected_files(fixtures_root: Path, expected_files: dict[str, str]) -> int:
    failures: list[str] = []

    for relpath, expected in sorted(expected_files.items()):
        path = fixtures_root / relpath
        if not path.exists():
            failures.append(f"missing file: {relpath}")
            continue
        actual = path.read_text(encoding="utf-8")
        expected_text = expected + "\n"
        if actual != expected_text:
            failures.append(f"content drift: {relpath}")
            diff = "\n".join(
                difflib.unified_diff(
                    expected_text.splitlines(),
                    actual.splitlines(),
                    fromfile=f"expected/{relpath}",
                    tofile=f"actual/{relpath}",
                    lineterm="",
                )
            )
            if diff:
                print(diff)

    expected_path_set = {fixtures_root / relpath for relpath in expected_files}
    for path in sorted(path for path in fixtures_root.rglob("*") if path.is_file()):
        if path not in expected_path_set:
            failures.append(f"unexpected file: {path.relative_to(fixtures_root).as_posix()}")

    if failures:
        for failure in failures:
            print(f"[migration-contract] {failure}", file=sys.stderr)
        return 1

    print(
        f"[migration-contract] fixture check ok ({len(expected_files)} files)."
    )
    return 0


def main() -> int:
    args = parse_args()

    base_cmd = shlex.split(args.python_cmd)
    if not base_cmd:
        raise SystemExit("error: --python-cmd resolved to an empty command")

    fixtures_root = args.fixtures_root.expanduser().resolve(strict=False)
    testbed_root = args.testbed_root.expanduser().resolve(strict=False)
    ruleset = args.ruleset.expanduser().resolve(strict=False)
    policy_path = args.policy_path.expanduser().resolve(strict=False)

    if not testbed_root.exists():
        raise SystemExit(f"error: testbed root does not exist: {testbed_root}")
    if not ruleset.exists():
        raise SystemExit(f"error: ruleset does not exist: {ruleset}")
    if not policy_path.exists():
        raise SystemExit(f"error: policy fixture does not exist: {policy_path}")

    selected_cases = (
        CONTRACT_CASES
        if not args.scenario
        else [CONTRACT_CASE_BY_NAME[name] for name in args.scenario]
    )
    expected_files = _build_expected_files(
        base_cmd=base_cmd,
        selected_cases=selected_cases,
        testbed_root=testbed_root,
        ruleset=ruleset,
        policy_path=policy_path,
    )

    if args.write:
        _write_expected_files(fixtures_root, expected_files)
        print(
            f"[migration-contract] wrote {len(expected_files)} fixture files under "
            f"{fixtures_root.relative_to(REPO_ROOT)}"
        )
        return 0

    if not fixtures_root.exists():
        print(
            f"[migration-contract] missing fixtures root: {fixtures_root.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1
    return _check_expected_files(fixtures_root, expected_files)


if __name__ == "__main__":
    raise SystemExit(main())
