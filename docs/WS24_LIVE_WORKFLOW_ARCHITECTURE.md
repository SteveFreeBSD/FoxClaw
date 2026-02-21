# WS-24: Live Workflow Architecture

Status: implemented.

## Purpose

`foxclaw live` provides an explicit network-enabled wrapper that runs:

1. `intel sync`
2. `scan` pinned to the newly generated snapshot

This keeps `scan` offline-by-default while giving operators a one-command
sync-then-scan workflow.

## Runtime Guardrails

- Separation of concerns:
  - `scan` remains offline-only.
  - network activity is isolated to `live` (sync step).
- Deterministic replay:
  - the sync output `snapshot_id` is carried directly into the scan call.
  - run output logs the pinned snapshot for reproducibility.
- Fail-closed behavior:
  - if sync fails, `live` exits operational error and does not run scan.

## Implemented CLI Surface

```bash
python -m foxclaw live \
  --source foxclaw-amo=tests/fixtures/intel/amo_extension_intel.v1.json \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml
```

Optional trust/suppression/report flags supported by `scan` are also exposed on
`live`.

## Evidence and Tests

- Implementation: `foxclaw/cli.py`
- Tests: `tests/test_live_orchestration.py`
- Workslice tracking: `docs/WORKSLICES.md` (WS-24)
