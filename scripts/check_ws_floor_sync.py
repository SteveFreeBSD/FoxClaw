#!/usr/bin/env python3
"""Check that WORKSLICES and PREMERGE reference the same validated WS floor."""

from __future__ import annotations

import re
from pathlib import Path

WS_RE = re.compile(r"WS-(\d+)")


def _extract_floor(path: Path, *, required_fragments: tuple[str, ...]) -> int:
    for line in path.read_text(encoding="utf-8").splitlines():
        if any(fragment not in line for fragment in required_fragments):
            continue
        values = [int(match.group(1)) for match in WS_RE.finditer(line)]
        if values:
            return max(values)
    raise SystemExit(f"error: unable to resolve WS floor from {path}")


def main() -> int:
    root = Path.cwd().resolve()
    workslices_path = root / "docs" / "WORKSLICES.md"
    premerge_path = root / "docs" / "PREMERGE_READINESS.md"

    workslices_floor = _extract_floor(
        workslices_path,
        required_fragments=("validated Python baseline", "WS-"),
    )
    premerge_floor = _extract_floor(
        premerge_path,
        required_fragments=("evidence review", "WS-"),
    )

    if workslices_floor != premerge_floor:
        print(
            "[ws-floor-sync] mismatch "
            f"workslices=WS-{workslices_floor} premerge=WS-{premerge_floor}"
        )
        return 1

    print(f"[ws-floor-sync] OK ws_floor=WS-{workslices_floor}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
