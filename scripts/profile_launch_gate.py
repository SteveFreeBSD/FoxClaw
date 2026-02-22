#!/usr/bin/env python3
"""Run generated Firefox profiles through a real Firefox generic launch to assert structural persistence."""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

# Try to import the static fidelity checker if in the same directory
try:
    from profile_fidelity_check import evaluate_profile
except ImportError:
    # If called from a weird path
    import sys
    sys.path.append(str(Path(__file__).parent))
    from profile_fidelity_check import evaluate_profile

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class LaunchGateResult:
    profile: str
    survived: bool
    firefox_exit_code: int
    duration_seconds: float
    fidelity_pre: int
    fidelity_post: int
    issues: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Profile directory or parent directory containing multiple profiles")
    parser.add_argument(
        "--pattern",
        default="*.synth-*",
        help="Glob pattern for profile subdirectories when path is a root directory",
    )
    parser.add_argument(
        "--firefox-bin",
        default="firefox",
        help="Path or name of the Firefox executable (default: firefox)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Seconds to allow headless Firefox to spin up and serialize to disk (default: 5)",
    )
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Exit non-zero if any profile fails to launch cleanly or drops below minimum fidelity",
    )
    parser.add_argument(
        "--min-post-score",
        type=int,
        default=50,
        help="Minimum realism score allowed *after* Firefox terminates (default: 50)",
    )
    parser.add_argument("--json-out", default="", help="Optional JSON output file")
    return parser.parse_args()


def _find_profiles(path: Path, pattern: str) -> list[Path]:
    if (path / "prefs.js").exists():
        return [path]
    return sorted(p for p in path.glob(pattern) if p.is_dir() and (p / "prefs.js").exists())


def execute_launch_gate(
    profile_dir: Path,
    firefox_bin: str,
    timeout_seconds: int,
    min_post_score: int,
) -> LaunchGateResult:
    """Run a single profile through the Firefox headless spin-up cycle."""
    issues: list[str] = []
    survived = True

    # 1. Base static fidelity score before we touch it
    pre_result = evaluate_profile(profile_dir)
    score_pre = pre_result.score

    # 2. Duplicate it to a temporary sandbox so we don't accidentally ruin the test fixture
    # if Firefox decides to delete everything. Use a random suffix for concurrent builds.
    tmp_parent = Path("/tmp")
    sandbox = tmp_parent / f"foxclaw-launch-gate-{profile_dir.name}-{uuid.uuid4().hex[:8]}"
    if sandbox.exists():
        shutil.rmtree(sandbox)
    shutil.copytree(profile_dir, sandbox)

    # 3. Launch Firefox headless pointing at the sandbox
    cmd = [
        firefox_bin,
        "--headless",
        "--no-remote",
        "--profile",
        str(sandbox),
        "about:blank",
    ]

    start_t = time.monotonic()
    firefox_exit = -1
    out_payload = ""
    try:
        # Run it and let it timeout. A timeout is actually a success, it means it started
        # and hung out waiting for instructions without crashing.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds, cwd="/tmp")
        firefox_exit = proc.returncode
        out_payload = proc.stderr
    except subprocess.TimeoutExpired as exc:
        firefox_exit = 0  # Expected for a browser we didn't tell to exit
        out_payload = (exc.stderr.decode("utf-8", errors="replace") if exc.stderr else "")
    except Exception as exc:
        issues.append(f"subprocess invocation failed: {exc}")
        survived = False

    duration = time.monotonic() - start_t

    # 4. Check for catastrophic aborts
    if firefox_exit != 0 and firefox_exit != 124: # 124 is standard timeout
        survived = False
        issues.append(f"Firefox crashed with exit code {firefox_exit}")
        if "Segmentation fault" in out_payload or "Abort" in out_payload:
            issues.append("Fatal native crash detected in stderr")

    # 5. Check post-launch fidelity (did Firefox delete our broken databases?)
    post_result = evaluate_profile(sandbox)
    score_post = post_result.score

    if score_post < min_post_score:
        survived = False
        issues.append(f"Fidelity dropped from {score_pre} to {score_post} (below minimum {min_post_score})")
        if pre_result.required_present["cookies.sqlite"] and not post_result.required_present["cookies.sqlite"]:
            issues.append("Firefox permanently deleted cookies.sqlite upon startup")
        if pre_result.required_present["places.sqlite"] and not post_result.required_present["places.sqlite"]:
            issues.append("Firefox permanently deleted places.sqlite upon startup")

    # Cleanup the sandbox
    try:
        shutil.rmtree(sandbox)
    except OSError:
        pass

    return LaunchGateResult(
        profile=str(profile_dir),
        survived=survived,
        firefox_exit_code=firefox_exit,
        duration_seconds=round(duration, 2),
        fidelity_pre=score_pre,
        fidelity_post=score_post,
        issues=issues,
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args()

    firefox_bin = args.firefox_bin
    if not shutil.which(firefox_bin):
        _LOG.warning(f"[launch-gate] SKIP: Firefox binary '{firefox_bin}' not found on host.")
        if args.enforce:
            return 1
        return 0

    root = Path(args.path)
    if not root.exists():
        _LOG.error(f"[launch-gate] error: path does not exist: {root}")
        return 1

    profiles = _find_profiles(root, args.pattern)
    if not profiles:
        _LOG.error(f"[launch-gate] error: no profiles found in {root} matching {args.pattern}")
        return 1

    results: list[LaunchGateResult] = []
    for profile in profiles:
        res = execute_launch_gate(
            profile,
            firefox_bin=firefox_bin,
            timeout_seconds=args.timeout,
            min_post_score=args.min_post_score,
        )
        results.append(res)
        
        status = "PASS" if res.survived else "FAIL"
        _LOG.info(
            f"[launch-gate] {status} {profile.name} (exit={res.firefox_exit_code} "
            f"fidelity: {res.fidelity_pre}->{res.fidelity_post} time: {res.duration_seconds}s)"
        )
        for issue in res.issues:
            _LOG.warning(f"  -> {issue}")

    failed = [r for r in results if not r.survived]
    
    payload = {
        "profiles_evaluated": len(results),
        "profiles_survived": len(results) - len(failed),
        "profiles_failed": len(failed),
        "min_post_score": args.min_post_score,
        "results": [asdict(r) for r in results],
    }

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    if args.enforce and failed:
        return 1
    return 0


if __name__ == "__main__":
    exit(main())
