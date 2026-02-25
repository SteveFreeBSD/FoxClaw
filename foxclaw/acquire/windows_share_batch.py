"""Batch orchestration for windows-share profile staging and scan runs."""

from __future__ import annotations

import concurrent.futures
import io
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import TextIO

from foxclaw.acquire.windows_share import parse_windows_share_scan_args, run_windows_share_scan

RunnerResult = tuple[int, str, str]
WindowsShareScanRunner = Callable[[list[str]], RunnerResult]


def _run_single_windows_share_scan(argv: list[str]) -> RunnerResult:
    args = parse_windows_share_scan_args(argv)
    out_buffer = io.StringIO()
    err_buffer = io.StringIO()
    exit_code = run_windows_share_scan(args, out_stream=out_buffer, err_stream=err_buffer)
    return (exit_code, out_buffer.getvalue(), err_buffer.getvalue())


def _extract_error_line(*, stdout_payload: str, stderr_payload: str) -> str | None:
    lines = [
        line.strip()
        for line in (stderr_payload + "\n" + stdout_payload).splitlines()
        if line.strip()
    ]
    if not lines:
        return None

    for line in reversed(lines):
        if line.lower().startswith("error:"):
            return line

    return lines[-1]


def _read_staged_path(profile_out: Path) -> str | None:
    manifest_path = profile_out / "stage-manifest.json"
    if not manifest_path.is_file():
        return None

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None

    staged_profile = payload.get("staged_profile")
    return staged_profile if isinstance(staged_profile, str) and staged_profile else None


def _build_windows_share_scan_argv(
    *,
    profile_dir: Path,
    profile_out: Path,
    staging_root: Path,
    snapshot_id: str,
    allow_active_profile: bool,
    foxclaw_cmd: str | None,
    ruleset: Path | None,
    policy_path: list[Path] | None,
    suppression_path: list[Path] | None,
    intel_store_dir: Path | None,
    intel_snapshot_id: str | None,
    keep_stage_writable: bool,
    dry_run: bool,
    treat_high_findings_as_success: bool,
) -> list[str]:
    argv = [
        "--source-profile",
        str(profile_dir),
        "--staging-root",
        str(staging_root),
        "--snapshot-id",
        snapshot_id,
        "--output-dir",
        str(profile_out),
    ]

    if foxclaw_cmd:
        argv.extend(["--foxclaw-cmd", foxclaw_cmd])
    if ruleset is not None:
        argv.extend(["--ruleset", str(ruleset)])

    for path in policy_path or []:
        argv.extend(["--policy-path", str(path)])
    for path in suppression_path or []:
        argv.extend(["--suppression-path", str(path)])

    if intel_store_dir is not None:
        argv.extend(["--intel-store-dir", str(intel_store_dir)])
    if intel_snapshot_id:
        argv.extend(["--intel-snapshot-id", intel_snapshot_id])
    if allow_active_profile:
        argv.append("--allow-active-profile")
    if keep_stage_writable:
        argv.append("--keep-stage-writable")
    if dry_run:
        argv.append("--dry-run")
    if treat_high_findings_as_success:
        argv.append("--treat-high-findings-as-success")

    return argv


def run_windows_share_batch(
    *,
    source_root: Path,
    staging_root: Path,
    out_root: Path,
    max_profiles: int | None = None,
    allow_active_profile: bool = False,
    snapshot_id_prefix: str | None = None,
    foxclaw_cmd: str | None = None,
    ruleset: Path | None = None,
    policy_path: list[Path] | None = None,
    suppression_path: list[Path] | None = None,
    intel_store_dir: Path | None = None,
    intel_snapshot_id: str | None = None,
    keep_stage_writable: bool = False,
    dry_run: bool = False,
    treat_high_findings_as_success: bool = False,
    workers: int = 1,
    runner: WindowsShareScanRunner = _run_single_windows_share_scan,
    out_stream: TextIO | None = None,
) -> int:
    out_stream = out_stream or io.StringIO()

    source_root = source_root.expanduser().resolve(strict=False)
    staging_root = staging_root.expanduser().resolve(strict=False)
    out_root = out_root.expanduser().resolve(strict=False)

    if not source_root.is_dir():
        raise ValueError(f"source root does not exist or is not a directory: {source_root}")
    if max_profiles is not None and max_profiles < 1:
        raise ValueError("--max must be greater than zero when provided")

    out_root.mkdir(parents=True, exist_ok=True)

    child_dirs = sorted(
        (path for path in source_root.iterdir() if path.is_dir()), key=lambda path: path.name
    )
    total_profiles_seen = len(child_dirs)
    selected_profiles = child_dirs[:max_profiles] if max_profiles is not None else child_dirs

    clean_count = 0
    findings_count = 0
    operational_failure_count = 0
    failures_by_error: dict[str, list[str]] = {}
    per_profile: list[dict[str, object]] = []
    started = perf_counter()
    batch_id = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")

    def _process_profile(index: int, profile_dir: Path) -> dict[str, object]:
        profile_name = profile_dir.name
        profile_out = out_root / profile_name
        profile_out.mkdir(parents=True, exist_ok=True)

        snapshot_base = snapshot_id_prefix or f"batch-{batch_id}"
        snapshot_id = f"{snapshot_base}-{index:04d}-{profile_name}"
        argv = _build_windows_share_scan_argv(
            profile_dir=profile_dir,
            profile_out=profile_out,
            staging_root=staging_root,
            snapshot_id=snapshot_id,
            allow_active_profile=allow_active_profile,
            foxclaw_cmd=foxclaw_cmd,
            ruleset=ruleset,
            policy_path=policy_path,
            suppression_path=suppression_path,
            intel_store_dir=intel_store_dir,
            intel_snapshot_id=intel_snapshot_id,
            keep_stage_writable=keep_stage_writable,
            dry_run=dry_run,
            treat_high_findings_as_success=treat_high_findings_as_success,
        )

        profile_started = perf_counter()
        try:
            exit_code, stdout_payload, stderr_payload = runner(argv)
        except Exception as exc:  # pragma: no cover
            exit_code = 1
            stdout_payload = ""
            stderr_payload = f"error: runner raised exception: {exc}"
        runtime_seconds = round(perf_counter() - profile_started, 3)

        error_line = _extract_error_line(
            stdout_payload=stdout_payload, stderr_payload=stderr_payload
        )
        staged_path = _read_staged_path(profile_out)

        profile_result: dict[str, object] = {
            "profile": profile_name,
            "exit_code": exit_code,
            "runtime_seconds": runtime_seconds,
        }
        if staged_path is not None:
            profile_result["staged_path"] = staged_path
        if error_line is not None and exit_code != 0:
            profile_result["error"] = error_line

        return profile_result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_to_index = {
            executor.submit(_process_profile, i, p_dir): (i, p_dir)
            for i, p_dir in enumerate(selected_profiles, start=1)
        }

        for future in concurrent.futures.as_completed(future_to_index):
            _, profile_dir = future_to_index[future]
            profile_name = profile_dir.name
            try:
                # 15-minute timeout per profile (includes heavy SQLite I/O)
                profile_result = future.result(timeout=900)
            except concurrent.futures.TimeoutError:
                profile_result = {
                    "profile": profile_name,
                    "exit_code": 1,
                    "runtime_seconds": 900.0,
                    "error": "error: profile scan timed out after 15 minutes",
                }
            except Exception as exc:  # pragma: no cover
                profile_result = {
                    "profile": profile_name,
                    "exit_code": 1,
                    "runtime_seconds": 0.0,
                    "error": f"error: unhandled worker exception: {exc}",
                }

            per_profile.append(profile_result)
            exit_code = profile_result["exit_code"]

            if exit_code == 0:
                clean_count += 1
            elif exit_code == 2:
                findings_count += 1
            else:
                operational_failure_count += 1
                normalized_error = str(profile_result.get("error", "error: operational failure"))
                failures_by_error.setdefault(normalized_error, []).append(profile_name)

            print(
                f"[share-batch] profile={profile_name} exit_code={exit_code} runtime_seconds={profile_result['runtime_seconds']:.3f}",
                file=out_stream,
            )

    # Sort per_profile alphabetically for consistent summary output
    per_profile.sort(key=lambda x: str(x["profile"]))

    runtime_seconds_total = round(perf_counter() - started, 3)
    summary_payload: dict[str, object] = {
        "total_profiles_seen": total_profiles_seen,
        "attempted": len(selected_profiles),
        "clean_count": clean_count,
        "findings_count": findings_count,
        "operational_failure_count": operational_failure_count,
        "failures_by_error": failures_by_error,
        "per_profile": per_profile,
        "runtime_seconds_total": runtime_seconds_total,
    }

    summary_path = out_root / "windows-share-batch-summary.json"
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"[share-batch] summary: {summary_path}", file=out_stream)

    if operational_failure_count > 0:
        return 1
    if findings_count > 0:
        return 2
    return 0
