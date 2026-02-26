# Issue: Clarify Determinism Contract vs Timestamp/Host/Path Variability

## Context
Ordering is deterministic, but default outputs include volatile fields (timestamps, host metadata, path normalization based on runtime context).

## Reproduction / Verification
- Inspect `generated_at` defaults and normalization roots in models/reporters.
- Compare outputs across different host/CWD conditions.

## Acceptance Criteria
- Determinism docs explicitly separate stable ordering from volatile metadata.
- Add tests that pin/verify behavior where deterministic mode applies.
- Ensure no silent contract ambiguity for CI consumers.

## Impacted Files
- `foxclaw/models.py`
- `foxclaw/cli.py`
- `foxclaw/report/sarif.py`
- `foxclaw/report/snapshot.py`
- `foxclaw/report/fleet.py`
- `docs/ARCHITECTURE.md`
- `docs/SCAN_LEARNING_LOOP.md`
