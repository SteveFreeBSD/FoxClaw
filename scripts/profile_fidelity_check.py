#!/usr/bin/env python3
"""Evaluate generated Firefox profile realism and structural fidelity."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path

REQUIRED_FILES = ("prefs.js", "places.sqlite", "cookies.sqlite")
OPTIONAL_REALISM_ARTIFACTS = (
    "addonStartup.json.lz4",
    "browser-extension-data",
    "cert9.db",
    "content-prefs.sqlite",
    "containers.json",
    "extension-preferences.json",
    "extension-settings.json",
    "extensions.json",
    "favicons.sqlite",
    "formhistory.sqlite",
    "handlers.json",
    "key4.db",
    "logins-backup.json",
    "logins.json",
    "permissions.sqlite",
    "SiteSecurityServiceState.txt",
    "storage/default",
    "pkcs11.txt",
    "search.json.mozlz4",
    "sessionstore-backups",
    "sessionstore.jsonlz4",
    "user.js",
    "xulstore.json",
)

PREF_PATTERN = re.compile(r'^user_pref\("[^\"]+",\s*.+\);$')


@dataclass(frozen=True)
class FidelityResult:
    profile: str
    score: int
    required_present: dict[str, bool]
    sqlite_ok: dict[str, bool]
    prefs_syntax_ok: bool
    extensions_consistent: bool
    optional_artifact_count: int
    optional_artifact_total: int
    issues: list[str]


def _sqlite_quick_check(path: Path) -> bool:
    try:
        conn = sqlite3.connect(path)
        try:
            cursor = conn.execute("PRAGMA quick_check")
            row = cursor.fetchone()
            return isinstance(row, tuple) and len(row) > 0 and row[0] == "ok"
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def _prefs_syntax_ok(path: Path) -> tuple[bool, list[str]]:
    issues: list[str] = []
    all_ok = True
    for name in ("prefs.js", "user.js"):
        pref_path = path / name
        if not pref_path.exists():
            if name == "prefs.js":
                all_ok = False
                issues.append("missing prefs.js")
            continue
        lines = pref_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if not PREF_PATTERN.match(stripped):
                all_ok = False
                issues.append(f"{name}:{line_no} invalid pref syntax")
                break
    return all_ok, issues


def _extensions_consistent(path: Path) -> tuple[bool, list[str]]:
    ext_json = path / "extensions.json"
    if not ext_json.exists():
        return True, []

    issues: list[str] = []
    try:
        payload = json.loads(ext_json.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return False, ["extensions.json parse error"]

    if not isinstance(payload, dict):
        return False, ["extensions.json top-level is not an object"]

    addons = payload.get("addons")
    if not isinstance(addons, list):
        return False, ["extensions.json missing addons list"]

    ok = True
    for index, addon in enumerate(addons):
        if not isinstance(addon, dict):
            ok = False
            issues.append(f"addons[{index}] is not an object")
            continue
        rel_path = addon.get("path")
        if isinstance(rel_path, str) and rel_path:
            if not (path / rel_path).exists():
                ok = False
                issues.append(f"addons[{index}] missing payload {rel_path}")
    return ok, issues


def evaluate_profile(path: Path) -> FidelityResult:
    required_present = {name: (path / name).exists() for name in REQUIRED_FILES}
    sqlite_ok = {
        "places.sqlite": _sqlite_quick_check(path / "places.sqlite") if required_present["places.sqlite"] else False,
        "cookies.sqlite": _sqlite_quick_check(path / "cookies.sqlite") if required_present["cookies.sqlite"] else False,
    }

    prefs_ok, pref_issues = _prefs_syntax_ok(path)
    ext_ok, ext_issues = _extensions_consistent(path)

    optional_hits = sum(1 for name in OPTIONAL_REALISM_ARTIFACTS if (path / name).exists())

    score = 0.0
    score += (sum(1 for present in required_present.values() if present) / len(required_present)) * 30.0
    score += (sum(1 for ok in sqlite_ok.values() if ok) / len(sqlite_ok)) * 20.0
    score += 15.0 if prefs_ok else 0.0
    score += 20.0 if ext_ok else 0.0
    score += (optional_hits / len(OPTIONAL_REALISM_ARTIFACTS)) * 15.0

    issues: list[str] = []
    issues.extend([f"missing {name}" for name, present in required_present.items() if not present])
    issues.extend([f"{name} quick_check failed" for name, ok in sqlite_ok.items() if not ok and required_present[name]])
    issues.extend(pref_issues)
    issues.extend(ext_issues)

    return FidelityResult(
        profile=str(path),
        score=round(score),
        required_present=required_present,
        sqlite_ok=sqlite_ok,
        prefs_syntax_ok=prefs_ok,
        extensions_consistent=ext_ok,
        optional_artifact_count=optional_hits,
        optional_artifact_total=len(OPTIONAL_REALISM_ARTIFACTS),
        issues=issues,
    )


def _find_profiles(path: Path, pattern: str) -> list[Path]:
    if any((path / file_name).exists() for file_name in REQUIRED_FILES):
        return [path]
    candidates = sorted(p for p in path.glob(pattern) if p.is_dir())
    profiles = [p for p in candidates if any((p / file_name).exists() for file_name in REQUIRED_FILES)]
    return profiles


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="Profile directory or parent directory containing profiles")
    parser.add_argument(
        "--pattern",
        default="*",
        help="Glob pattern for profile subdirectories when path is a root directory",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=70,
        help="Minimum realism score expected when using --enforce-min-score",
    )
    parser.add_argument(
        "--enforce-min-score",
        action="store_true",
        help="Exit non-zero if any evaluated profile score is below --min-score",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON summary to stdout")
    parser.add_argument("--json-out", default="", help="Optional JSON output file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.path)
    if not root.exists():
        raise SystemExit(f"error: path does not exist: {root}")

    profiles = _find_profiles(root, args.pattern)
    if not profiles:
        raise SystemExit(f"error: no profile directories found under: {root}")

    results = [evaluate_profile(profile) for profile in profiles]

    below = [result for result in results if result.score < args.min_score]
    for result in results:
        status = "PASS" if result.score >= args.min_score else "WARN"
        print(
            f"[fidelity] {status} profile={Path(result.profile).name} "
            f"score={result.score} optional={result.optional_artifact_count}/{result.optional_artifact_total}"
        )
        if result.issues:
            print("[fidelity] issues=" + "; ".join(result.issues[:5]))

    payload = {
        "min_score": args.min_score,
        "profiles": [asdict(result) for result in results],
        "average_score": round(sum(result.score for result in results) / len(results), 2),
        "below_min_count": len(below),
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    if args.enforce_min_score and below:
        return 1
    return 0


if __name__ == "__main__":
    exit(main())
