# Pre-Merge Readiness Plan

This runbook defines the expanded checks required before approving a merge that is intended for release-track branches.

## Required Gate Set

Run from repository root.

1. Full certification:

```bash
./scripts/certify.sh
```

2. Extended live-profile/snapshot validation (profile override allowed for deterministic local rehearsal):

```bash
./scripts/certify.sh --with-live-profile --profile tests/fixtures/firefox_profile
```

3. Dependency vulnerability sweep:

```bash
make dep-audit
```

4. Packaging dry-run and install smoke test:

```bash
python -m pip install --upgrade build twine
rm -rf build dist
python -m build
python -m twine check dist/*
```

Install the built wheel into a clean venv and verify CLI import/entrypoint:

```bash
tmp_venv="$(mktemp -d)"
python3 -m venv "${tmp_venv}/venv"
"${tmp_venv}/venv/bin/pip" install dist/*.whl
"${tmp_venv}/venv/bin/foxclaw" --help
rm -rf "${tmp_venv}"
```

5. SBOM generation and verification:

```bash
make sbom
make sbom-verify
```

## Merge Hold Criteria

Do not merge when any of the following is true:

- any required gate fails.
- fixture drift is present and not intentionally committed.
- docs are out of sync with CLI/workflow/schema surfaces.
- release tag/version plan is unresolved.

## Immediate Planning Queue

Ordered next implementation targets:

1. **WS-57**: Unblock quality gates (`ruff`, `detect-secrets`) and keep CI/local parity.
2. **WS-58**: Fix exit-code contract mismatches for operational errors.
3. **WS-59**: Align UNC fail-closed behavior and lock-marker handling across command paths.
4. **WS-60 + WS-61**: Correct learning-store determinism gaps and synchronize docs to runtime behavior.
5. **WS-55B**: Continue trend/novelty enrichment only after WS-57..WS-61 are complete.
6. **WS-47..WS-53**: Continue pending threat-surface collectors/rules with deterministic regression tests.
7. **WS-31 + WS-32**: Rust workspace bootstrap and contract canonicalization lock for migration parity.

Current evidence basis:

- `docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md` confirms stability and highlights
  runtime bottleneck concentration in fuzz workloads.
- `docs/AUDIT_2026-02-24.md` defines mandatory closeout work before next comprehensive audit.
