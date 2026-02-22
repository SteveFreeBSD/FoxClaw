#!/usr/bin/env python3
"""Run deterministic parity checks between Python and Rust CLI engines."""

from __future__ import annotations

import argparse
import difflib
import json
import shlex
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from migration_contract_common import (  # noqa: E402
    CONTRACT_CASES,
    REPO_ROOT,
    TESTBED_POLICY,
    TESTBED_ROOT,
    TESTBED_RULESET,
    stage_contract_case_profile,
)


@dataclass(frozen=True)
class ParityCase:
    name: str
    profile_name: str
    with_policy_path: bool
    expected_exit_code: int


@dataclass(frozen=True)
class EngineRun:
    engine: str
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    json_path: str
    sarif_path: str
    launch_error: str | None
    json_parse_error: str | None
    sarif_parse_error: str | None


CASES: list[ParityCase] = [
    ParityCase(
        case.name,
        case.profile_name,
        case.with_policy_path,
        case.expected_exit_code,
    )
    for case in CONTRACT_CASES
]
CASE_BY_NAME = {case.name: case for case in CASES}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python-cmd",
        default=".venv/bin/python -m foxclaw",
        help="Base Python engine command (default: .venv/bin/python -m foxclaw)",
    )
    parser.add_argument(
        "--rust-cmd",
        default=(
            "cargo run --quiet --manifest-path foxclaw-rs/Cargo.toml "
            "-p foxclaw-rs-cli --"
        ),
        help="Base Rust engine command (default: cargo run ... foxclaw-rs-cli --)",
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
        choices=sorted(CASE_BY_NAME),
        default=[],
        help="Run only selected scenario(s); repeatable",
    )
    parser.add_argument(
        "--skip-sarif",
        action="store_true",
        help="Skip SARIF comparison and only compare JSON outputs",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/foxclaw-rs-parity"),
        help="Directory for parity artifacts (default: /tmp/foxclaw-rs-parity)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path for summary JSON (default: <output-dir>/summary.json)",
    )
    return parser.parse_args()


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _load_json(path: Path) -> tuple[object | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)


def _write_diff(path: Path, left: str, right: str, *, left_name: str, right_name: str) -> bool:
    diff_lines = list(
        difflib.unified_diff(
            left.splitlines(),
            right.splitlines(),
            fromfile=left_name,
            tofile=right_name,
            lineterm="",
        )
    )
    if not diff_lines:
        return False
    preview_limit = 200
    clipped = diff_lines[:preview_limit]
    if len(diff_lines) > preview_limit:
        clipped.append("... diff truncated ...")
    path.write_text("\n".join(clipped) + "\n", encoding="utf-8")
    return True


def _build_scan_command(
    *,
    base_cmd: list[str],
    profile_path: Path,
    ruleset: Path,
    policy_path: Path,
    json_out: Path,
    sarif_out: Path,
    with_policy_path: bool,
) -> list[str]:
    cmd = [
        *base_cmd,
        "scan",
        "--profile",
        str(profile_path),
        "--ruleset",
        str(ruleset),
        "--json",
        "--deterministic",
        "--output",
        str(json_out),
        "--sarif-out",
        str(sarif_out),
    ]
    if with_policy_path:
        cmd.extend(["--policy-path", str(policy_path)])
    return cmd


def _run_engine(
    *,
    engine_name: str,
    base_cmd: list[str],
    profile_path: Path,
    with_policy_path: bool,
    ruleset: Path,
    policy_path: Path,
    case_dir: Path,
) -> tuple[EngineRun, object | None, object | None]:
    json_out = case_dir / f"{engine_name}.json"
    sarif_out = case_dir / f"{engine_name}.sarif"
    cmd = _build_scan_command(
        base_cmd=base_cmd,
        profile_path=profile_path,
        ruleset=ruleset,
        policy_path=policy_path,
        json_out=json_out,
        sarif_out=sarif_out,
        with_policy_path=with_policy_path,
    )
    try:
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        run = EngineRun(
            engine=engine_name,
            command=cmd,
            exit_code=1,
            stdout="",
            stderr="",
            json_path=str(json_out),
            sarif_path=str(sarif_out),
            launch_error=str(exc),
            json_parse_error=None,
            sarif_parse_error=None,
        )
        return run, None, None

    json_payload, json_error = _load_json(json_out)
    sarif_payload, sarif_error = _load_json(sarif_out)
    run = EngineRun(
        engine=engine_name,
        command=cmd,
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        json_path=str(json_out),
        sarif_path=str(sarif_out),
        launch_error=None,
        json_parse_error=json_error,
        sarif_parse_error=sarif_error,
    )
    return run, json_payload, sarif_payload


def main() -> int:
    args = parse_args()

    selected_cases = CASES if not args.scenario else [CASE_BY_NAME[name] for name in args.scenario]
    output_dir = args.output_dir.expanduser().resolve(strict=False)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = (
        args.json_out.expanduser().resolve(strict=False)
        if args.json_out is not None
        else output_dir / "summary.json"
    )

    python_cmd = shlex.split(args.python_cmd)
    rust_cmd = shlex.split(args.rust_cmd)
    if not python_cmd:
        raise SystemExit("error: --python-cmd resolved to an empty command")
    if not rust_cmd:
        raise SystemExit("error: --rust-cmd resolved to an empty command")

    testbed_root = args.testbed_root.expanduser().resolve(strict=False)
    ruleset = args.ruleset.expanduser().resolve(strict=False)
    policy_path = args.policy_path.expanduser().resolve(strict=False)
    if not testbed_root.exists():
        raise SystemExit(f"error: testbed root does not exist: {testbed_root}")
    if not ruleset.exists():
        raise SystemExit(f"error: ruleset does not exist: {ruleset}")
    if not policy_path.exists():
        raise SystemExit(f"error: policy fixture does not exist: {policy_path}")

    results: list[dict[str, object]] = []
    failed = 0
    compare_sarif = not args.skip_sarif

    for case in selected_cases:
        case_dir = output_dir / case.name
        case_dir.mkdir(parents=True, exist_ok=True)
        profile_path = stage_contract_case_profile(
            case=case,
            testbed_root=testbed_root,
            work_root=case_dir,
        )

        py_run, py_json, py_sarif = _run_engine(
            engine_name="python",
            base_cmd=python_cmd,
            profile_path=profile_path,
            with_policy_path=case.with_policy_path,
            ruleset=ruleset,
            policy_path=policy_path,
            case_dir=case_dir,
        )
        rs_run, rs_json, rs_sarif = _run_engine(
            engine_name="rust",
            base_cmd=rust_cmd,
            profile_path=profile_path,
            with_policy_path=case.with_policy_path,
            ruleset=ruleset,
            policy_path=policy_path,
            case_dir=case_dir,
        )

        issues: list[str] = []
        if py_run.launch_error:
            issues.append(f"python launch failed: {py_run.launch_error}")
        if rs_run.launch_error:
            issues.append(f"rust launch failed: {rs_run.launch_error}")
        if py_run.json_parse_error:
            issues.append(f"python JSON parse failed: {py_run.json_parse_error}")
        if rs_run.json_parse_error:
            issues.append(f"rust JSON parse failed: {rs_run.json_parse_error}")
        if compare_sarif and py_run.sarif_parse_error:
            issues.append(f"python SARIF parse failed: {py_run.sarif_parse_error}")
        if compare_sarif and rs_run.sarif_parse_error:
            issues.append(f"rust SARIF parse failed: {rs_run.sarif_parse_error}")

        if py_run.exit_code != rs_run.exit_code:
            issues.append(
                f"exit-code mismatch: python={py_run.exit_code} rust={rs_run.exit_code}"
            )
        if py_run.exit_code != case.expected_exit_code:
            issues.append(
                f"python exit-code drift: expected={case.expected_exit_code} got={py_run.exit_code}"
            )
        if rs_run.exit_code != case.expected_exit_code:
            issues.append(
                f"rust exit-code drift: expected={case.expected_exit_code} got={rs_run.exit_code}"
            )

        if py_json is not None and rs_json is not None:
            py_json_text = _canonical_json(py_json)
            rs_json_text = _canonical_json(rs_json)
            if py_json_text != rs_json_text:
                diff_path = case_dir / "json.diff"
                _write_diff(
                    diff_path,
                    py_json_text,
                    rs_json_text,
                    left_name="python.json",
                    right_name="rust.json",
                )
                issues.append(f"JSON payload mismatch (diff: {diff_path})")

        if compare_sarif and py_sarif is not None and rs_sarif is not None:
            py_sarif_text = _canonical_json(py_sarif)
            rs_sarif_text = _canonical_json(rs_sarif)
            if py_sarif_text != rs_sarif_text:
                diff_path = case_dir / "sarif.diff"
                _write_diff(
                    diff_path,
                    py_sarif_text,
                    rs_sarif_text,
                    left_name="python.sarif",
                    right_name="rust.sarif",
                )
                issues.append(f"SARIF payload mismatch (diff: {diff_path})")

        status = "PASS" if not issues else "FAIL"
        if status == "FAIL":
            failed += 1

        print(
            f"[parity] {status} case={case.name} expected_exit={case.expected_exit_code} "
            f"python_exit={py_run.exit_code} rust_exit={rs_run.exit_code}"
        )
        for issue in issues:
            print(f"[parity]   issue: {issue}")

        results.append(
            {
                "case": asdict(case),
                "status": status,
                "issues": issues,
                "python": asdict(py_run),
                "rust": asdict(rs_run),
            }
        )

    summary = {
        "cases_total": len(selected_cases),
        "cases_passed": len(selected_cases) - failed,
        "cases_failed": failed,
        "compare_sarif": compare_sarif,
        "python_cmd": python_cmd,
        "rust_cmd": rust_cmd,
        "output_dir": str(output_dir),
        "results": results,
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[parity] summary: {summary_path}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
