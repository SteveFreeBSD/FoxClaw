#!/usr/bin/env python3
"""Orchestrate the Windows-share presoak and detached comprehensive soak."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_PREFLIGHT_CMD = f"bash {SCRIPT_DIR / 'windows_share_preflight.sh'}"
DEFAULT_SCAN_CMD = f"{sys.executable} -m foxclaw"
DEFAULT_BATCH_CMD = f"{sys.executable} -m foxclaw acquire windows-share-batch"
DEFAULT_FLEET_SMOKE_CMD = f"{sys.executable} {SCRIPT_DIR / 'siem_elastic_fleet_smoke.py'}"
DEFAULT_LAUNCHER_CMD = "systemd-run --user"
DEFAULT_FLEET_PROFILE = REPO_ROOT / "tests" / "fixtures" / "firefox_profile"
DEFAULT_FLEET_RULESET = REPO_ROOT / "foxclaw" / "rulesets" / "balanced.yml"
DEFAULT_FLEET_PRESOAK_TIMEOUT_SECONDS = 60
DEFAULT_FLEET_PRESOAK_RETRY_DELAY_SECONDS = 15


@dataclass(frozen=True)
class CorpusProfile:
    name: str
    classification: str
    included: bool
    performance_baseline_excluded: bool


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path("/mnt/firefox-profiles"))
    parser.add_argument(
        "--staging-root", type=Path, default=Path("/var/tmp/foxclaw-stage-comprehensive")
    )
    parser.add_argument(
        "--share-out-root",
        type=Path,
        default=Path("/var/tmp/foxclaw-share-batch-comprehensive"),
    )
    parser.add_argument(
        "--presoak-root",
        type=Path,
        default=Path("/var/tmp/foxclaw-presoak-share"),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("/var/tmp/foxclaw-soak"),
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=None,
        help="Manifest path (defaults under --output-root with a timestamped name).",
    )
    parser.add_argument(
        "--corpus-mode",
        choices=("mixed", "generated-only"),
        default="mixed",
        help="Profile inclusion policy for the share-batch sanity pass.",
    )
    parser.add_argument(
        "--exclude-profile-name",
        action="append",
        default=[],
        help="Optional repeatable profile directory name to exclude from the batch sanity gate.",
    )
    parser.add_argument(
        "--presoak-profile",
        default=None,
        help="Optional explicit profile directory name for the direct staged presoak scan.",
    )
    parser.add_argument(
        "--lock-policy",
        choices=("fail-closed", "allow-active"),
        default="fail-closed",
        help="Lock-marker policy for presoak and share-batch staging.",
    )
    parser.add_argument(
        "--batch-high-findings-policy",
        choices=("success", "scan-exit"),
        default="success",
        help="How the bounded share-batch sanity gate treats per-profile HIGH findings.",
    )
    parser.add_argument(
        "--max-batch-profiles",
        type=int,
        default=5,
        help="Number of included profiles to exercise in the bounded share-batch sanity gate.",
    )
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--profile-timeout-seconds", type=int, default=900)
    parser.add_argument("--duration-hours", type=int, default=10)
    parser.add_argument("--stage-timeout-seconds", type=int, default=1800)
    parser.add_argument("--siem-wazuh-runs", type=int, default=1)
    parser.add_argument("--siem-elastic-fleet-runs", type=int, default=0)
    parser.add_argument(
        "--label",
        default="windows-share-comprehensive",
        help="Soak label forwarded to scripts/soak_runner.sh.",
    )
    parser.add_argument(
        "--unit-name",
        default=None,
        help="Optional explicit systemd unit name for the detached soak service.",
    )
    parser.add_argument(
        "--launch-timeout-seconds",
        type=int,
        default=10,
        help="How long to wait for the launched soak run directory to appear.",
    )
    parser.add_argument(
        "--soak-extra-arg",
        action="append",
        default=[],
        help="Optional repeatable extra argument forwarded to scripts/soak_runner.sh.",
    )
    parser.add_argument(
        "--preflight-cmd",
        default=DEFAULT_PREFLIGHT_CMD,
        help="Command prefix used for the windows-share preflight script.",
    )
    parser.add_argument(
        "--scan-cmd",
        default=DEFAULT_SCAN_CMD,
        help="Command prefix used for the direct FoxClaw presoak scan.",
    )
    parser.add_argument(
        "--batch-cmd",
        default=DEFAULT_BATCH_CMD,
        help="Command prefix used for foxclaw acquire windows-share-batch.",
    )
    parser.add_argument(
        "--launcher-cmd",
        default=DEFAULT_LAUNCHER_CMD,
        help="Command prefix used to launch the detached long soak.",
    )
    parser.add_argument(
        "--fleet-smoke-cmd",
        default=DEFAULT_FLEET_SMOKE_CMD,
        help="Command prefix used for the Elastic Fleet presoak smoke runner.",
    )
    parser.add_argument(
        "--fleet-profile",
        type=Path,
        default=DEFAULT_FLEET_PROFILE,
        help="Firefox profile used for the Elastic Fleet presoak smoke run.",
    )
    parser.add_argument(
        "--fleet-ruleset",
        type=Path,
        default=DEFAULT_FLEET_RULESET,
        help="Ruleset used for the Elastic Fleet presoak smoke run.",
    )
    parser.add_argument(
        "--fleet-presoak-timeout-seconds",
        type=int,
        default=DEFAULT_FLEET_PRESOAK_TIMEOUT_SECONDS,
        help="Timeout budget for the Elastic Fleet presoak smoke run.",
    )
    parser.add_argument(
        "--soak-runner",
        type=Path,
        default=SCRIPT_DIR / "soak_runner.sh",
        help="Path to the soak runner script launched after presoak gates pass.",
    )
    return parser.parse_args(argv)


def _sanitize_label(label: str) -> str:
    lowered = label.lower()
    sanitized = re.sub(r"[^a-z0-9._-]+", "-", lowered).strip("-")
    return sanitized or "run"


def _classify_profile_name(name: str) -> tuple[str, bool]:
    if re.fullmatch(r"foxclaw-gen-\d+\.default", name):
        return ("generated", False)
    if name == "foxclaw-seed.default":
        return ("seed", True)
    if name == "b67gz6f3.default":
        return ("degenerate_stub", True)
    return ("other", False)


def _plan_corpus(
    source_root: Path,
    *,
    corpus_mode: str,
    excluded_names: set[str],
) -> list[CorpusProfile]:
    profiles: list[CorpusProfile] = []
    for path in sorted(
        (candidate for candidate in source_root.iterdir() if candidate.is_dir() and not candidate.name.startswith(".")),
        key=lambda candidate: candidate.name,
    ):
        classification, baseline_excluded = _classify_profile_name(path.name)
        included = path.name not in excluded_names and (
            corpus_mode == "mixed" or classification == "generated"
        )
        profiles.append(
            CorpusProfile(
                name=path.name,
                classification=classification,
                included=included,
                performance_baseline_excluded=baseline_excluded,
            )
        )
    return profiles


def _select_presoak_profile(
    profiles: list[CorpusProfile], explicit_name: str | None
) -> str:
    included = [profile for profile in profiles if profile.included]
    if not included:
        raise ValueError("no profiles matched the current corpus policy")
    if explicit_name is not None:
        for profile in included:
            if profile.name == explicit_name:
                return profile.name
        raise ValueError(f"presoak profile is not included by current policy: {explicit_name}")
    generated = [profile.name for profile in included if profile.classification == "generated"]
    if generated:
        return generated[0]
    return included[0].name


def _run_command(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _parse_preflight_stdout(stdout: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in stdout.splitlines():
        if not line.startswith("[windows-share-preflight] "):
            continue
        payload = line.removeprefix("[windows-share-preflight] ")
        if "=" not in payload:
            continue
        key, value = payload.split("=", 1)
        parsed[key] = value
    return parsed


def _write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_environment_file(values: dict[str, str]) -> Path:
    fd, raw_path = tempfile.mkstemp(prefix="foxclaw-windows-share-soak-env-", text=True)
    path = Path(raw_path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for key in sorted(values):
                handle.write(f"{key}={shlex.quote(values[key])}\n")
        path.chmod(0o600)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _redact_sensitive_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    for arg in argv:
        if arg.startswith("--setenv=SOAK_SUDO_PASSWORD="):
            redacted.append("--setenv=SOAK_SUDO_PASSWORD=<redacted>")
        elif arg.startswith("--property=EnvironmentFile="):
            redacted.append("--property=EnvironmentFile=<redacted>")
        else:
            redacted.append(arg)
    return redacted


def _resolve_run_dir(
    *,
    output_root: Path,
    label: str,
    known_runs: set[str],
    timeout_seconds: int,
) -> str:
    safe_label = _sanitize_label(label)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() <= deadline:
        candidates = sorted(
            (
                path
                for path in output_root.glob(f"*{safe_label}*")
                if path.is_dir() and str(path) not in known_runs
            ),
            key=lambda path: path.name,
        )
        if candidates:
            return str(candidates[-1])
        time.sleep(0.1)
    raise RuntimeError(
        f"unable to resolve new soak run directory under {output_root} for label {label!r}"
    )


def _batch_summary_view(summary_path: Path) -> dict[str, Any]:
    payload = json.loads(summary_path.read_text(encoding="utf-8"))
    return {
        "summary_path": str(summary_path),
        "attempted": payload.get("attempted"),
        "clean_count": payload.get("clean_count"),
        "findings_count": payload.get("findings_count"),
        "operational_failure_count": payload.get("operational_failure_count"),
        "runtime_seconds_total": payload.get("runtime_seconds_total"),
    }


def _fleet_presoak_retry_delay_seconds() -> int:
    raw = os.environ.get("FOXCLAW_FLEET_PRESOAK_RETRY_DELAY_SECONDS")
    if raw is None:
        return DEFAULT_FLEET_PRESOAK_RETRY_DELAY_SECONDS
    try:
        delay = int(raw)
    except ValueError:
        return DEFAULT_FLEET_PRESOAK_RETRY_DELAY_SECONDS
    return delay if delay >= 0 else DEFAULT_FLEET_PRESOAK_RETRY_DELAY_SECONDS


def _is_retryable_fleet_presoak_failure(result: subprocess.CompletedProcess[str]) -> bool:
    stderr = result.stderr.lower()
    return result.returncode == 124 or "offline" in stderr


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    launch_id = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")

    source_root = args.source_root.expanduser().resolve(strict=False)
    staging_root = args.staging_root.expanduser().resolve(strict=False)
    share_out_root = args.share_out_root.expanduser().resolve(strict=False)
    presoak_root = args.presoak_root.expanduser().resolve(strict=False)
    output_root = args.output_root.expanduser().resolve(strict=False)
    manifest_out = (
        args.manifest_out.expanduser().resolve(strict=False)
        if args.manifest_out is not None
        else output_root / f"windows-share-comprehensive-{launch_id}.json"
    )
    soak_runner = args.soak_runner.expanduser().resolve(strict=False)

    if args.max_batch_profiles < 1:
        raise SystemExit("error: --max-batch-profiles must be greater than zero")
    if args.workers < 1:
        raise SystemExit("error: --workers must be greater than zero")
    if args.profile_timeout_seconds < 1:
        raise SystemExit("error: --profile-timeout-seconds must be greater than zero")
    if args.duration_hours < 1:
        raise SystemExit("error: --duration-hours must be greater than zero")
    if args.stage_timeout_seconds < 1:
        raise SystemExit("error: --stage-timeout-seconds must be greater than zero")
    if args.launch_timeout_seconds < 1:
        raise SystemExit("error: --launch-timeout-seconds must be greater than zero")
    if args.fleet_presoak_timeout_seconds < 1:
        raise SystemExit("error: --fleet-presoak-timeout-seconds must be greater than zero")
    if not source_root.is_dir():
        raise SystemExit(f"error: source root does not exist: {source_root}")
    if not soak_runner.is_file():
        raise SystemExit(f"error: soak runner not found: {soak_runner}")
    if args.siem_elastic_fleet_runs > 0:
        fleet_profile = args.fleet_profile.expanduser().resolve(strict=False)
        fleet_ruleset = args.fleet_ruleset.expanduser().resolve(strict=False)
        if not fleet_profile.is_dir():
            raise SystemExit(f"error: Fleet presoak profile not found: {fleet_profile}")
        if not fleet_ruleset.is_file():
            raise SystemExit(f"error: Fleet presoak ruleset not found: {fleet_ruleset}")
    else:
        fleet_profile = args.fleet_profile.expanduser().resolve(strict=False)
        fleet_ruleset = args.fleet_ruleset.expanduser().resolve(strict=False)

    excluded_names = {name.strip() for name in args.exclude_profile_name if name.strip()}
    corpus_profiles = _plan_corpus(
        source_root,
        corpus_mode=args.corpus_mode,
        excluded_names=excluded_names,
    )
    if not corpus_profiles:
        raise SystemExit(f"error: no profile directories found under {source_root}")

    presoak_profile = _select_presoak_profile(corpus_profiles, args.presoak_profile)
    included_profiles = [profile.name for profile in corpus_profiles if profile.included]
    corpus_counts = Counter(profile.classification for profile in corpus_profiles)
    performance_excluded = [
        profile.name
        for profile in corpus_profiles
        if profile.performance_baseline_excluded
    ]

    output_root.mkdir(parents=True, exist_ok=True)
    share_out_root.mkdir(parents=True, exist_ok=True)
    presoak_root.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "launch_id": launch_id,
        "source_root": str(source_root),
        "staging_root": str(staging_root),
        "share_out_root": str(share_out_root),
        "presoak_root": str(presoak_root),
        "output_root": str(output_root),
        "corpus_mode": args.corpus_mode,
        "lock_policy": args.lock_policy,
        "batch_high_findings_policy": args.batch_high_findings_policy,
        "presoak_profile": presoak_profile,
        "corpus_counts": {key: corpus_counts[key] for key in sorted(corpus_counts)},
        "performance_baseline_excluded_profiles": performance_excluded,
        "profiles": [asdict(profile) for profile in corpus_profiles],
        "steps": {},
    }
    _write_manifest(manifest_out, manifest)

    preflight_cmd = [*shlex.split(args.preflight_cmd), str(source_root)]
    preflight_result = _run_command(preflight_cmd)
    manifest["steps"]["preflight"] = {
        "argv": preflight_cmd,
        "exit_code": preflight_result.returncode,
        "stdout": preflight_result.stdout,
        "stderr": preflight_result.stderr,
        "parsed": _parse_preflight_stdout(preflight_result.stdout),
    }
    _write_manifest(manifest_out, manifest)
    if preflight_result.returncode != 0:
        raise SystemExit(preflight_result.returncode)

    presoak_dir = presoak_root / presoak_profile
    presoak_dir.mkdir(parents=True, exist_ok=True)
    presoak_cmd = [
        *shlex.split(args.scan_cmd),
        "scan",
        "--profile",
        str(source_root / presoak_profile),
        "--output",
        str(presoak_dir / "foxclaw.json"),
        "--sarif-out",
        str(presoak_dir / "foxclaw.sarif"),
        "--snapshot-out",
        str(presoak_dir / "foxclaw.snapshot.json"),
        "--stage-manifest-out",
        str(presoak_dir / "stage-manifest.json"),
    ]
    if args.lock_policy == "allow-active":
        presoak_cmd.append("--allow-active-profile")
    presoak_result = _run_command(presoak_cmd)
    manifest["steps"]["presoak"] = {
        "argv": presoak_cmd,
        "exit_code": presoak_result.returncode,
        "stdout": presoak_result.stdout,
        "stderr": presoak_result.stderr,
        "artifact_root": str(presoak_dir),
    }
    _write_manifest(manifest_out, manifest)
    if presoak_result.returncode not in (0, 2):
        raise SystemExit(presoak_result.returncode)

    batch_cmd = [
        *shlex.split(args.batch_cmd),
        "--source-root",
        str(source_root),
        "--staging-root",
        str(staging_root),
        "--out-root",
        str(share_out_root),
        "--max",
        str(args.max_batch_profiles),
        "--workers",
        str(args.workers),
        "--profile-timeout-seconds",
        str(args.profile_timeout_seconds),
    ]
    if args.lock_policy == "allow-active":
        batch_cmd.append("--allow-active-profile")
    if args.batch_high_findings_policy == "success":
        batch_cmd.append("--treat-high-findings-as-success")
    for profile_name in included_profiles:
        batch_cmd.extend(["--include-profile-name", profile_name])

    batch_result = _run_command(batch_cmd)
    summary_path = share_out_root / "windows-share-batch-summary.json"
    manifest["steps"]["batch"] = {
        "argv": batch_cmd,
        "exit_code": batch_result.returncode,
        "stdout": batch_result.stdout,
        "stderr": batch_result.stderr,
    }
    if summary_path.is_file():
        manifest["steps"]["batch"]["summary"] = _batch_summary_view(summary_path)
    _write_manifest(manifest_out, manifest)
    if batch_result.returncode != 0:
        raise SystemExit(batch_result.returncode)

    if args.siem_elastic_fleet_runs > 0:
        fleet_presoak_dir = presoak_root / "elastic-fleet"
        fleet_presoak_cmd = [
            *shlex.split(args.fleet_smoke_cmd),
            "--output-dir",
            str(fleet_presoak_dir),
            "--profile",
            str(fleet_profile),
            "--ruleset",
            str(fleet_ruleset),
            "--timeout-seconds",
            str(args.fleet_presoak_timeout_seconds),
        ]
        fleet_presoak_attempts: list[dict[str, Any]] = []
        fleet_presoak_result = _run_command(fleet_presoak_cmd)
        fleet_presoak_attempts.append(
            {
                "attempt": 1,
                "exit_code": fleet_presoak_result.returncode,
                "stdout": fleet_presoak_result.stdout,
                "stderr": fleet_presoak_result.stderr,
            }
        )
        if _is_retryable_fleet_presoak_failure(fleet_presoak_result):
            time.sleep(_fleet_presoak_retry_delay_seconds())
            fleet_presoak_result = _run_command(fleet_presoak_cmd)
            fleet_presoak_attempts.append(
                {
                    "attempt": 2,
                    "exit_code": fleet_presoak_result.returncode,
                    "stdout": fleet_presoak_result.stdout,
                    "stderr": fleet_presoak_result.stderr,
                }
            )
        manifest["steps"]["fleet_presoak"] = {
            "argv": fleet_presoak_cmd,
            "exit_code": fleet_presoak_result.returncode,
            "stdout": fleet_presoak_result.stdout,
            "stderr": fleet_presoak_result.stderr,
            "artifact_root": str(fleet_presoak_dir),
            "attempts": fleet_presoak_attempts,
        }
        fleet_manifest_path = fleet_presoak_dir / "manifest.json"
        if fleet_manifest_path.is_file():
            fleet_manifest = _read_json(fleet_manifest_path)
            manifest["steps"]["fleet_presoak"]["summary"] = {
                "status": fleet_manifest.get("status"),
                "run_id": fleet_manifest.get("run_id"),
                "target_agent_id": fleet_manifest.get("target_agent_id"),
                "expected_index_name": fleet_manifest.get("expected_index_name"),
                "count_before": fleet_manifest.get("count_before"),
                "count_after": fleet_manifest.get("count_after"),
                "new_documents": fleet_manifest.get("new_documents"),
            }
        _write_manifest(manifest_out, manifest)
        if fleet_presoak_result.returncode != 0:
            raise SystemExit(fleet_presoak_result.returncode)
        fleet_summary = manifest["steps"]["fleet_presoak"].get("summary")
        if not isinstance(fleet_summary, dict):
            raise SystemExit("error: Elastic Fleet presoak did not produce a manifest summary")
        if fleet_summary.get("status") != "PASS":
            raise SystemExit("error: Elastic Fleet presoak did not report PASS")
        if not isinstance(fleet_summary.get("new_documents"), int) or fleet_summary["new_documents"] <= 0:
            raise SystemExit("error: Elastic Fleet presoak did not ingest new documents")

    known_runs = {
        str(path)
        for path in output_root.glob(f"*{_sanitize_label(args.label)}*")
        if path.is_dir()
    }
    unit_name = args.unit_name or f"foxclaw-soak-windows-share-{launch_id.lower()}"
    launch_cmd = [
        *shlex.split(args.launcher_cmd),
        "--unit",
        unit_name,
        "--same-dir",
        "--collect",
    ]
    launch_env = os.environ.copy()
    environment_file: Path | None = None
    if "SOAK_SUDO_PASSWORD" in launch_env:
        environment_file = _write_environment_file(
            {"SOAK_SUDO_PASSWORD": launch_env.pop("SOAK_SUDO_PASSWORD")}
        )
        launch_cmd.append(f"--property=EnvironmentFile={environment_file}")
    launch_cmd.extend(
        [
            str(soak_runner),
            "--duration-hours",
            str(args.duration_hours),
            "--stage-timeout-seconds",
            str(args.stage_timeout_seconds),
            "--siem-wazuh-runs",
            str(args.siem_wazuh_runs),
            "--siem-elastic-fleet-runs",
            str(args.siem_elastic_fleet_runs),
            "--label",
            args.label,
            "--output-root",
            str(output_root),
        ]
    )
    launch_cmd.extend(args.soak_extra_arg)
    try:
        launch_result = _run_command(launch_cmd, env=launch_env)
        manifest["steps"]["soak_launch"] = {
            "argv": _redact_sensitive_argv(launch_cmd),
            "exit_code": launch_result.returncode,
            "stdout": launch_result.stdout,
            "stderr": launch_result.stderr,
            "unit_name": unit_name,
        }
        if launch_result.returncode != 0:
            _write_manifest(manifest_out, manifest)
            raise SystemExit(launch_result.returncode)

        run_dir = _resolve_run_dir(
            output_root=output_root,
            label=args.label,
            known_runs=known_runs,
            timeout_seconds=args.launch_timeout_seconds,
        )
        manifest["steps"]["soak_launch"]["run_dir"] = run_dir
        _write_manifest(manifest_out, manifest)
    finally:
        if environment_file is not None:
            environment_file.unlink(missing_ok=True)

    print(f"[windows-share-comprehensive] manifest={manifest_out}")
    print(f"[windows-share-comprehensive] presoak_profile={presoak_profile}")
    print(f"[windows-share-comprehensive] batch_summary={summary_path}")
    print(f"[windows-share-comprehensive] soak_unit={unit_name}")
    print(f"[windows-share-comprehensive] soak_run_dir={run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
