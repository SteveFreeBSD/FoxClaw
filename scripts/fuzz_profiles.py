#!/usr/bin/env python3
"""FoxClaw randomized Firefox profile fuzzer with reproducible mutation provenance."""

from __future__ import annotations

import argparse
import logging
import os
import random
import time
from pathlib import Path
from sys import exit

from profile_generation_common import (
    SCENARIOS,
    AMOFetcher,
    apply_mutations,
    choose_scenario,
    fuzz_profile_name,
    generate_realistic_profile,
    load_catalog,
    write_metadata,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=10,
        help="Number of fuzzed profiles to generate (default: 10)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="/tmp/foxclaw-fuzzer-profiles",
        help="Target directory for generated profiles",
    )
    parser.add_argument(
        "--mode",
        choices=("realistic", "chaos"),
        default="chaos",
        help="Fuzz mode; chaos applies heavier mutation pressure",
    )
    parser.add_argument(
        "--scenario",
        choices=tuple(SCENARIOS.keys()),
        default=None,
        help="Force one scenario for all generated profiles",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Deterministic seed for reproducible generation",
    )
    parser.add_argument(
        "--catalog-path",
        type=str,
        default="",
        help="Optional extension catalog snapshot JSON path",
    )
    parser.add_argument(
        "--allow-network-fetch",
        action="store_true",
        help="Allow live AMO fetches for uncached extensions (disabled by default)",
    )
    parser.add_argument(
        "--mutation-budget",
        type=int,
        default=3,
        help="Base mutation budget per profile (default: 3)",
    )
    parser.add_argument(
        "--max-mutation-severity",
        choices=("low", "medium", "high"),
        default="high",
        help="Highest mutation severity allowed",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress log output")
    return parser.parse_args()


def _inject_chaos_noise(profile_dir: Path, rng: random.Random) -> list[dict[str, object]]:
    operations: list[dict[str, object]] = []

    if rng.random() < 0.35:
        target = profile_dir / "extensions.json"
        if target.exists():
            content = target.read_text(encoding="utf-8", errors="replace")
            target.write_text(content + "\n{BROKEN", encoding="utf-8")
            operations.append({"operator": "append_garbage_json", "severity": "high", "target": "extensions.json"})

    if rng.random() < 0.30:
        target = profile_dir / "prefs.js"
        if target.exists():
            target.write_text(target.read_text(encoding="utf-8", errors="replace") + "\nuser_pref(\"broken\", ;\n", encoding="utf-8")
            operations.append({"operator": "append_broken_pref", "severity": "medium", "target": "prefs.js"})

    if rng.random() < 0.25:
        crash = profile_dir / "crashes" / "events.log"
        crash.parent.mkdir(parents=True, exist_ok=True)
        crash.write_bytes(os.urandom(rng.randint(128, 2048)))
        operations.append({"operator": "random_crash_blob", "severity": "low", "target": "crashes/events.log"})

    return operations


def main() -> int:
    args = parse_args()
    if args.count < 0:
        raise SystemExit("--count must be non-negative")
    if args.mutation_budget < 0:
        raise SystemExit("--mutation-budget must be non-negative")

    logging.basicConfig(
        level=logging.ERROR if args.quiet else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    base_seed = args.seed if args.seed is not None else int.from_bytes(os.urandom(8), "big")

    catalog_path = Path(args.catalog_path) if args.catalog_path else None
    catalog_version, catalog = load_catalog(catalog_path)
    fetcher = AMOFetcher(
        Path("/tmp/foxclaw-amo-cache"),
        catalog,
        allow_network=args.allow_network_fetch,
    )

    logging.info("FoxClaw fuzz starting. target=%s", output_dir)
    logging.info(
        "config mode=%s count=%s seed=%s scenario=%s mutation_budget=%s max_mutation_severity=%s catalog=%s",
        args.mode,
        args.count,
        base_seed,
        args.scenario or "auto",
        args.mutation_budget,
        args.max_mutation_severity,
        catalog_version,
    )

    for index in range(args.count):
        profile_seed = base_seed + index
        rng = random.Random(profile_seed)
        scenario = choose_scenario(index=index, rng=rng, forced=args.scenario)
        profile_dir = output_dir / fuzz_profile_name(index)

        metadata = generate_realistic_profile(
            profile_dir=profile_dir,
            scenario=scenario,
            rng=rng,
            fetcher=fetcher,
            mode=f"fuzz-{args.mode}",
        )

        budget = args.mutation_budget
        if args.mode == "chaos":
            budget += rng.randint(1, 3)

        mutations = apply_mutations(
            profile_dir=profile_dir,
            rng=rng,
            mutation_budget=budget,
            max_severity=args.max_mutation_severity,
        )
        if args.mode == "chaos":
            mutations.extend(_inject_chaos_noise(profile_dir, rng))

        metadata.update(
            {
                "seed": profile_seed,
                "catalog_version": catalog_version,
                "mutation_budget": budget,
                "max_mutation_severity": args.max_mutation_severity,
                "mutations": mutations,
                "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )
        write_metadata(profile_dir, metadata)

    logging.info("Generated %s fuzzed profiles.", args.count)
    return 0


if __name__ == "__main__":
    exit(main())
