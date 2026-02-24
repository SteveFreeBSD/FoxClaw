#!/usr/bin/env python3
"""Generate adversarial Firefox profiles and run FoxClaw scans against them."""

from __future__ import annotations

import argparse
import json
import random
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from profile_generation_common import (
    SCENARIOS,
    AMOFetcher,
    apply_mutations,
    generate_realistic_profile,
    load_catalog,
    write_metadata,
)

DEFAULT_SCENARIOS = ("compromised", "enterprise_managed", "developer_heavy", "privacy_hardened")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="/tmp/foxclaw-adversary-profiles",
        help="Directory for generated profiles and summary outputs.",
    )
    parser.add_argument(
        "--count-per-scenario",
        type=int,
        default=2,
        help="Profiles generated per scenario (default: 2).",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenarios",
        default=[],
        choices=tuple(SCENARIOS.keys()),
        help="Repeatable scenario override. Defaults to curated adversary matrix.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=606060,
        help="Deterministic base seed (default: 606060).",
    )
    parser.add_argument(
        "--mutation-budget",
        type=int,
        default=3,
        help="Mutations per generated profile (default: 3).",
    )
    parser.add_argument(
        "--max-mutation-severity",
        choices=("low", "medium", "high"),
        default="high",
        help="Highest mutation severity allowed (default: high).",
    )
    parser.add_argument(
        "--ruleset",
        default="foxclaw/rulesets/strict.yml",
        help="Ruleset used for each scan (default: foxclaw/rulesets/strict.yml).",
    )
    parser.add_argument(
        "--foxclaw-cmd",
        default=f"{sys.executable} -m foxclaw",
        help="FoxClaw invocation command prefix (default: current python -m foxclaw).",
    )
    parser.add_argument(
        "--catalog-path",
        default="",
        help="Optional extension catalog snapshot JSON path.",
    )
    parser.add_argument(
        "--allow-network-fetch",
        action="store_true",
        help="Allow live AMO fetches for uncached extension IDs.",
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help="Keep existing output dir content; default removes it for deterministic runs.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress per-profile progress output.")
    return parser.parse_args()


def _extract_error_line(stdout_payload: str, stderr_payload: str) -> str | None:
    lines = [line.strip() for line in (stderr_payload + "\n" + stdout_payload).splitlines() if line.strip()]
    if not lines:
        return None

    for line in reversed(lines):
        if "Operational error:" in line or line.lower().startswith("error:"):
            return line
    return lines[-1]


def _scan_profile(
    *,
    foxclaw_cmd: str,
    ruleset: Path,
    profile_dir: Path,
) -> tuple[int, dict[str, Any] | None, str | None]:
    cmd = [
        *shlex.split(foxclaw_cmd),
        "scan",
        "--profile",
        str(profile_dir),
        "--ruleset",
        str(ruleset),
        "--json",
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)

    payload: dict[str, Any] | None = None
    if result.returncode in (0, 2):
        try:
            decoded = json.loads(result.stdout)
            if isinstance(decoded, dict):
                payload = decoded
        except json.JSONDecodeError:
            payload = None

    error_line = _extract_error_line(result.stdout, result.stderr)
    return (result.returncode, payload, error_line)


def main() -> int:
    args = parse_args()
    if args.count_per_scenario < 1:
        raise SystemExit("--count-per-scenario must be greater than zero")
    if args.mutation_budget < 0:
        raise SystemExit("--mutation-budget must be non-negative")

    selected_scenarios = tuple(args.scenarios) if args.scenarios else DEFAULT_SCENARIOS
    for scenario_name in selected_scenarios:
        if scenario_name not in SCENARIOS:
            raise SystemExit(f"unknown scenario: {scenario_name}")

    output_dir = Path(args.output_dir).expanduser().resolve(strict=False)
    if output_dir.exists() and not args.keep_existing:
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    catalog_path = Path(args.catalog_path).expanduser().resolve(strict=False) if args.catalog_path else None
    catalog_version, catalog = load_catalog(catalog_path)
    fetcher = AMOFetcher(
        Path("/tmp/foxclaw-amo-cache"),
        catalog,
        allow_network=args.allow_network_fetch,
    )

    ruleset_path = Path(args.ruleset).expanduser().resolve(strict=False)
    if not ruleset_path.is_file():
        raise SystemExit(f"ruleset path does not exist: {ruleset_path}")

    clean_count = 0
    findings_count = 0
    operational_failure_count = 0
    failures_by_error: dict[str, list[str]] = {}
    per_profile: list[dict[str, Any]] = []
    started = time.perf_counter()

    profile_index = 0
    for scenario_offset, scenario_name in enumerate(selected_scenarios):
        scenario = SCENARIOS[scenario_name]
        for ordinal in range(args.count_per_scenario):
            profile_seed = args.seed + (scenario_offset * 10_000) + ordinal
            rng = random.Random(profile_seed)
            profile_name = f"{profile_index:04d}-{scenario_name}.adv-{profile_seed}"
            profile_dir = output_dir / profile_name
            profile_index += 1

            metadata = generate_realistic_profile(
                profile_dir=profile_dir,
                scenario=scenario,
                rng=rng,
                fetcher=fetcher,
                mode="adversary",
            )
            mutations = apply_mutations(
                profile_dir=profile_dir,
                rng=rng,
                mutation_budget=args.mutation_budget,
                max_severity=args.max_mutation_severity,
            )
            metadata.update(
                {
                    "seed": profile_seed,
                    "catalog_version": catalog_version,
                    "generator_mode": "adversary",
                    "mutation_budget": args.mutation_budget,
                    "max_mutation_severity": args.max_mutation_severity,
                    "mutations": mutations,
                    "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            )
            write_metadata(profile_dir, metadata)

            scan_started = time.perf_counter()
            exit_code, payload, error_line = _scan_profile(
                foxclaw_cmd=args.foxclaw_cmd,
                ruleset=ruleset_path,
                profile_dir=profile_dir,
            )
            runtime_seconds = round(time.perf_counter() - scan_started, 3)
            findings_high_count: int | None = None
            findings_total: int | None = None
            if payload is not None:
                summary = payload.get("summary", {})
                if isinstance(summary, dict):
                    raw_high = summary.get("findings_high_count")
                    raw_total = summary.get("findings_total")
                    findings_high_count = int(raw_high) if isinstance(raw_high, int) else None
                    findings_total = int(raw_total) if isinstance(raw_total, int) else None

            profile_record: dict[str, Any] = {
                "profile": profile_name,
                "scenario": scenario_name,
                "seed": profile_seed,
                "exit_code": exit_code,
                "runtime_seconds": runtime_seconds,
                "findings_high_count": findings_high_count,
                "findings_total": findings_total,
            }
            if error_line is not None and exit_code not in (0, 2):
                profile_record["error"] = error_line
            per_profile.append(profile_record)

            if exit_code == 0:
                clean_count += 1
            elif exit_code == 2:
                findings_count += 1
            else:
                operational_failure_count += 1
                normalized_error = error_line or "error: foxclaw scan operational failure"
                failures_by_error.setdefault(normalized_error, []).append(profile_name)

            if not args.quiet:
                print(
                    "[adversary] profile="
                    f"{profile_name} scenario={scenario_name} exit_code={exit_code} "
                    f"runtime_seconds={runtime_seconds:.3f}"
                )

    runtime_seconds_total = round(time.perf_counter() - started, 3)
    summary_payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "catalog_version": catalog_version,
        "ruleset": str(ruleset_path),
        "scenarios": list(selected_scenarios),
        "count_per_scenario": args.count_per_scenario,
        "profiles_total": len(per_profile),
        "clean_count": clean_count,
        "findings_count": findings_count,
        "operational_failure_count": operational_failure_count,
        "failures_by_error": failures_by_error,
        "runtime_seconds_total": runtime_seconds_total,
        "per_profile": per_profile,
    }

    summary_path = output_dir / "adversary-summary.json"
    summary_path.write_text(
        json.dumps(summary_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not args.quiet:
        print(f"[adversary] summary: {summary_path}")

    return 1 if operational_failure_count > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
