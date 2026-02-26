# Issue: Deduplicate `scan`/`live` CLI Orchestration

## Context
`scan` and `live` replicate profile resolution, safety checks, trust verification, and output write logic in separate blocks.

## Reproduction / Verification
- Compare `foxclaw/cli.py` scan and live command bodies.
- Track duplicated behavior blocks and drift-prone logic.

## Acceptance Criteria
- Shared internal executor handles common scan orchestration.
- `live` remains sync-first with pinned snapshot injection.
- Existing CLI exit-code and determinism tests remain green.

## Impacted Files
- `foxclaw/cli.py`
- `tests/test_cli_exit_codes.py`
- `tests/test_live_orchestration.py`
- `tests/test_determinism.py`
