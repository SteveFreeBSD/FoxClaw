"""Deterministic trend-direction helpers (WS-55B)."""

from __future__ import annotations

from typing import Literal

TrendDirection = Literal["new_profile", "improving", "stable", "degrading"]


def compute_trend_direction(
    *,
    latest_present: bool,
    previous_present: bool | None,
) -> TrendDirection:
    """Compute trend direction from adjacent history snapshots.

    - `new_profile`: only one snapshot is available.
    - `degrading`: finding appears in latest snapshot after being absent.
    - `improving`: finding disappears in latest snapshot after being present.
    - `stable`: no change between previous and latest snapshots.
    """
    if previous_present is None:
        return "new_profile"
    if latest_present and not previous_present:
        return "degrading"
    if not latest_present and previous_present:
        return "improving"
    return "stable"
