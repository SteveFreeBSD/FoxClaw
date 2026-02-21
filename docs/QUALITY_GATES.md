# Quality Gates

This document is the release-quality contract for local development and milestone delivery.

## Gate Philosophy

- Run deterministic checks first (lint, typecheck, tests).
- Run security and dead-code checks before merge.
- Validate fixture and live profile runtime paths.
- Do not push if any gate fails.

## Required Local Gates

Run from repository root:

```bash
make certify
```

This runs:

- `ruff check .`
- `mypy foxclaw`
- `pytest -q -m "not integration"`
- `python scripts/generate_testbed_fixtures.py --write`
- `python scripts/generate_testbed_fixtures.py --check`
- fixture tree clean (`git diff --quiet -- tests/fixtures/testbed`)
- `pytest -q -m integration`
- fixture scan (`scripts/fixture_scan.sh`)
- `bandit -q -r foxclaw -x tests`
- `vulture foxclaw tests --min-confidence 80`
- `detect-secrets scan --exclude-files '^tests/fixtures/testbed/manifest\.json$' $(git ls-files)`
- cleanup (`make clean`)

## Live Profile Validation Gate

Before milestone completion and push:

```bash
make certify-live
```

This adds:

- two local profile scans with deterministic snapshot output.
- snapshot diff smoke test on those snapshots.
- parse validation of emitted artifacts.

Notes:

- Live profile findings can legitimately change if your profile changes between scans.
- The gate verifies command health, output validity, and deterministic behavior of the diff engine.

## Git Hook Enforcement

Install pre-push hook once per clone:

```bash
make hooks-install
```

The pre-push hook runs `./scripts/certify.sh` automatically.

## Push Readiness Checklist

- `make certify` passes.
- `make certify-live` passes for release/milestone branches.
- `git status --short` is clean.
- Docs updated for any CLI, schema, or trust-boundary change.
- Commit messages are scoped and auditable.

## CI Parity

Local gates should stay aligned with CI jobs.  
When adding or removing checks, update:

- `Makefile`
- `scripts/certify.sh`
- `.github/workflows/foxclaw-security.yml`
- this document.

CI-only dependency policy gate:

- Pull requests enforce dependency review in `dependency-policy` job
  (`actions/dependency-review-action` with high-severity failure policy).
  This gate has no exact local offline equivalent and is enforced in GitHub Actions.
- Scheduled dependency vulnerability sweeps run in
  `.github/workflows/foxclaw-dependency-audit.yml`.
  Local equivalent is available with `make dep-audit`.
