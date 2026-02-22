#!/usr/bin/env python3
"""Verify one engine command against canonical WS-32 migration fixtures."""

from __future__ import annotations

import argparse
import difflib
import json
import shlex
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from migration_contract_common import (  # noqa: E402
    CONTRACT_CASE_BY_NAME,
    CONTRACT_CASES,
    MIGRATION_CONTRACT_FIXTURES_ROOT,
    REPO_ROOT,
    TESTBED_POLICY,
    TESTBED_ROOT,
    TESTBED_RULESET,
    ContractCase,
    normalize_contract_payload,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine-cmd",
        required=True,
        help="Engine command to validate (e.g. '.venv/bin/python -m foxclaw')",
    )
    parser.add_argument(
        "--fixtures-root",
        type=Path,
        default=MIGRATION_CONTRACT_FIXTURES_ROOT,
        help="Root directory containing canonical migration contract fixtures",
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
        help="Verify only selected scenario(s); repeatable",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/foxclaw-contract-verify"),
        help="Directory for per-case compare artifacts",
    )
    parser.add_argument(
        "--engine-label",
        default="engine",
        help="Label used in logs and artifact filenames",
    )
    return parser.parse_args()


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


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


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"failed to parse JSON file {path}: {exc}") from exc


def _write_diff(path: Path, *, expected: str, observed: str, expected_name: str, observed_name: str) -> None:
    lines = list(
        difflib.unified_diff(
            expected.splitlines(),
            observed.splitlines(),
            fromfile=expected_name,
            tofile=observed_name,
            lineterm="",
        )
    )
    preview = lines[:200]
    if len(lines) > 200:
        preview.append("... diff truncated ...")
    path.write_text("\n".join(preview) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    base_cmd = shlex.split(args.engine_cmd)
    if not base_cmd:
        raise SystemExit("error: --engine-cmd resolved to an empty command")

    fixtures_root = args.fixtures_root.expanduser().resolve(strict=False)
    testbed_root = args.testbed_root.expanduser().resolve(strict=False)
    ruleset = args.ruleset.expanduser().resolve(strict=False)
    policy_path = args.policy_path.expanduser().resolve(strict=False)
    output_dir = args.output_dir.expanduser().resolve(strict=False)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not fixtures_root.exists():
        raise SystemExit(f"error: fixtures root does not exist: {fixtures_root}")
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
    failed = 0

    for case in selected_cases:
        case_dir = output_dir / case.name
        case_dir.mkdir(parents=True, exist_ok=True)
        json_out = case_dir / f"{args.engine_label}.scan.json"
        sarif_out = case_dir / f"{args.engine_label}.scan.sarif"

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

        issues: list[str] = []
        if proc.returncode != case.expected_exit_code:
            issues.append(
                f"exit-code drift: expected={case.expected_exit_code} got={proc.returncode}"
            )

        try:
            observed_json = _load_json(json_out)
            observed_sarif = _load_json(sarif_out)
        except RuntimeError as exc:
            issues.append(str(exc))
            observed_json = None
            observed_sarif = None

        if observed_json is not None:
            observed_json_text = _canonical_json(
                normalize_contract_payload(observed_json, repo_root=REPO_ROOT)
            )
            expected_json_path = fixtures_root / "cases" / case.name / "scan.json"
            expected_json_text = expected_json_path.read_text(encoding="utf-8")
            if observed_json_text != expected_json_text:
                diff_path = case_dir / "json.diff"
                _write_diff(
                    diff_path,
                    expected=expected_json_text,
                    observed=observed_json_text,
                    expected_name=f"expected/{case.name}/scan.json",
                    observed_name=f"{args.engine_label}/{case.name}/scan.json",
                )
                issues.append(f"JSON drift (diff: {diff_path})")

        if observed_sarif is not None:
            observed_sarif_text = _canonical_json(
                normalize_contract_payload(observed_sarif, repo_root=REPO_ROOT)
            )
            expected_sarif_path = fixtures_root / "cases" / case.name / "scan.sarif"
            expected_sarif_text = expected_sarif_path.read_text(encoding="utf-8")
            if observed_sarif_text != expected_sarif_text:
                diff_path = case_dir / "sarif.diff"
                _write_diff(
                    diff_path,
                    expected=expected_sarif_text,
                    observed=observed_sarif_text,
                    expected_name=f"expected/{case.name}/scan.sarif",
                    observed_name=f"{args.engine_label}/{case.name}/scan.sarif",
                )
                issues.append(f"SARIF drift (diff: {diff_path})")

        status = "PASS" if not issues else "FAIL"
        print(
            f"[contract-verify] {status} case={case.name} "
            f"expected_exit={case.expected_exit_code} observed_exit={proc.returncode}"
        )
        for issue in issues:
            print(f"[contract-verify]   issue: {issue}")
        if issues:
            failed += 1

    print(
        f"[contract-verify] summary: engine={args.engine_label} "
        f"cases_total={len(selected_cases)} cases_failed={failed} output_dir={output_dir}"
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
