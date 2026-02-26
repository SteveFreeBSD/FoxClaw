# Issue: Documentation Contract Drift (README/PREMERGE/Gates)

## Status
Resolved on 2026-02-26.

## Context
Multiple docs are stale against code/workflow truth (workslice range, queue state, detect-secrets exclusions, live-intel command name).

## Reproduction / Verification
- `rg -n "WS-01 through|Immediate Planning Queue|detect-secrets scan --exclude-files|audit --live-intel" README.md docs`
- Compare with `scripts/check_secrets.sh` and `.github/workflows/foxclaw-security.yml`.

## Acceptance Criteria
- README, PREMERGE, QUALITY_GATES, GITHUB_ACTIONS, and VULNERABILITY_INTEL align with runtime/workflow behavior.
- Add one canonical CLI contract doc and make docs link to it.

## Impacted Files
- `README.md`
- `docs/PREMERGE_READINESS.md`
- `docs/QUALITY_GATES.md`
- `docs/GITHUB_ACTIONS.md`
- `docs/VULNERABILITY_INTEL.md`
- `docs/WORKSLICES.md`
