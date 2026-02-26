"""Deterministic novelty scoring helpers (WS-55B)."""

from __future__ import annotations


def compute_novelty_score(*, prior_hits: int, prior_scans: int) -> float:
    """Compute novelty score in [0.0, 1.0] from prior snapshot history.

    - `1.0`: first seen in latest snapshot (never seen in prior scans).
    - `0.0`: seen in every prior scan.
    """
    if prior_scans <= 0:
        return 1.0

    bounded_hits = min(max(prior_hits, 0), prior_scans)
    return round(1.0 - (bounded_hits / prior_scans), 4)
