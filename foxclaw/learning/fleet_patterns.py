"""Deterministic fleet prevalence and correlation helpers (WS-56)."""

from __future__ import annotations

from typing import Literal

LOW_PREVALENCE_THRESHOLD = 0.2

FleetPriority = Literal["normal", "elevated"]


def compute_fleet_prevalence(*, profiles_with_finding: int, total_profiles: int) -> float:
    """Compute prevalence in [0.0, 1.0] with deterministic rounding."""
    if total_profiles <= 0:
        return 0.0

    bounded = min(max(profiles_with_finding, 0), total_profiles)
    return round(bounded / total_profiles, 4)


def is_low_prevalence_outlier(
    *,
    fleet_prevalence: float,
    total_profiles: int,
    low_prevalence_threshold: float = LOW_PREVALENCE_THRESHOLD,
) -> bool:
    """Flag low-prevalence findings as fleet outliers.

    Outlier classification is disabled when only one profile is present.
    """
    if total_profiles <= 1:
        return False
    bounded = max(0.0, min(fleet_prevalence, 1.0))
    return bounded <= low_prevalence_threshold


def compute_outlier_priority(
    *,
    fleet_prevalence: float,
    total_profiles: int,
    low_prevalence_threshold: float = LOW_PREVALENCE_THRESHOLD,
) -> FleetPriority:
    """Apply deterministic priority elevation for low-prevalence outliers."""
    return (
        "elevated"
        if is_low_prevalence_outlier(
            fleet_prevalence=fleet_prevalence,
            total_profiles=total_profiles,
            low_prevalence_threshold=low_prevalence_threshold,
        )
        else "normal"
    )


def compute_pairwise_jaccard(*, intersection_count: int, union_count: int) -> float:
    """Compute deterministic Jaccard similarity in [0.0, 1.0]."""
    if union_count <= 0:
        return 0.0
    bounded = min(max(intersection_count, 0), union_count)
    return round(bounded / union_count, 4)
