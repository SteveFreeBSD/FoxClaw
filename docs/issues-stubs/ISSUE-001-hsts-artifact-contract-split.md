# Issue: Normalize `SiteSecurityServiceState` Contract (`.bin` vs `.txt`)

## Status
Resolved on 2026-02-26.

## Context
`collect_profile_artifacts()` now treats `SiteSecurityServiceState.txt` as canonical and keeps `.bin` support for legacy captures.

## Reproduction / Verification
- `rg -n "SiteSecurityServiceState\.(txt|bin)" foxclaw scripts docs tests | sort`
- Confirm `.txt` canonical references across generator/fidelity/docs and dual-read compatibility in collector.

## Acceptance Criteria
- One canonical filename contract is chosen and documented.
- Collector, generation scripts, fidelity checker, and docs all align.
- Regression tests cover artifact presence and collection behavior.

## Impacted Files
- `foxclaw/collect/artifacts.py`
- `scripts/profile_generation_common.py`
- `scripts/profile_fidelity_check.py`
- `docs/PROFILE_SYNTHESIS.md`
- `docs/PROFILE_FIDELITY_SPEC.md`
- `docs/SOAK.md`
