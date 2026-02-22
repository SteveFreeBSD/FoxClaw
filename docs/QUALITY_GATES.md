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
- migration contract fixtures write/check (`scripts/generate_migration_contract_fixtures.py`)
- migration contract fixture tree clean (`git diff --quiet -- tests/fixtures/migration_contracts`)
- migration contract verification against Python engine (`scripts/verify_migration_contract_engine.py`)
- fixture scan (`scripts/fixture_scan.sh`)
- trust-boundary scan smoke (`scripts/trust_scan_smoke.sh`)
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
- `make rust-parity-testbed` passes when Rust bridge/parity code paths change.
- extended pre-merge rehearsal passes when used:
  - `./scripts/certify.sh --with-live-profile --profile tests/fixtures/firefox_profile`
  - `make dep-audit`
  - packaging dry-run (`python -m build` + `twine check dist/*`)
  - SBOM rehearsal (`make sbom` + `make sbom-verify`)
- `git status --short` is clean.
- Docs updated for any CLI, schema, or trust-boundary change.
- Commit messages are scoped and auditable.

For full merge-hold workflow and immediate planning queue, see:

- `docs/PREMERGE_READINESS.md`

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
- Migration contract fixture drift gate runs in `integration-testbed`
  (`generate_migration_contract_fixtures.py --check` + fixture cleanliness check).
  Local equivalent command is:
  - `make migration-contract-fixtures`
- Rust parity gate runs in `rust-parity-testbed` (`cargo check` + deterministic
  Python-vs-Rust parity harness over testbed fixtures).
  Local equivalent commands are:
  - `make rust-workspace-check`
  - `make rust-parity-testbed`
- Scheduled dependency vulnerability sweeps run in
  `.github/workflows/foxclaw-dependency-audit.yml`.
  Local equivalent is available with `make dep-audit`.
