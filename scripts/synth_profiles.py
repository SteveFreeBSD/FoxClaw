#!/usr/bin/env python3
"""FoxClaw realistic synthetic Firefox profile generator."""

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
    generate_realistic_profile,
    load_catalog,
    synth_profile_name,
    write_metadata,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=5,
        help="Number of synthetic profiles to generate (default: 5)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="/tmp/foxclaw-synth-profiles",
        help="Target directory for generated profiles",
    )
    parser.add_argument(
        "--mode",
        choices=("realistic", "bootstrap"),
        default="realistic",
        help="Generation mode; bootstrap adds extra startup artifacts",
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
        default=0,
        help="Number of controlled mutations to apply per profile",
    )
    parser.add_argument(
        "--max-mutation-severity",
        choices=("low", "medium", "high"),
        default="medium",
        help="Highest mutation severity allowed",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress log output")
    return parser.parse_args()


def _bootstrap_augment(profile_dir: Path) -> None:
    # These are common profile-adjacent files produced by Firefox startup flows.
    (profile_dir / "compatibility.ini").write_text(
        "[Compatibility]\n"
        "LastVersion=136.0_20260220000000/20260220000000\n"
        "LastOSABI=Linux_x86_64-gcc3\n",
        encoding="utf-8",
    )
    (profile_dir / "times.json").write_text(
        '{"created": 1700000000000, "firstUse": 1700000000000}\n',
        encoding="utf-8",
    )


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

    logging.info("FoxClaw synth starting. target=%s", output_dir)
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
        profile_dir = output_dir / synth_profile_name(index=index, rng=rng)

        metadata = generate_realistic_profile(
            profile_dir=profile_dir,
            scenario=scenario,
            rng=rng,
            fetcher=fetcher,
            mode=args.mode,
        )
        if args.mode == "bootstrap":
            _bootstrap_augment(profile_dir)

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
                "mutation_budget": args.mutation_budget,
                "max_mutation_severity": args.max_mutation_severity,
                "mutations": mutations,
                "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )
        write_metadata(profile_dir, metadata)

    logging.info("Generated %s synthetic profiles.", args.count)
    return 0


if __name__ == "__main__":
    exit(main())
