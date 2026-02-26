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

## Current Execution Queue (2026-02-26)

Ordered next implementation targets:

1. **WS-55B**: Implement deterministic trend/novelty enrichment on top of the WS-55A history store.
2. **WS-56**: Add fleet prevalence/correlation once WS-55B data quality is proven.
3. **WS-47..WS-54**: Resume threat-surface collector/rule expansion with deterministic regression tests.
4. **WS-31 + WS-32**: Keep Rust workspace bootstrap + contract canonicalization on the critical path for migration parity.

Current evidence basis:

- `docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md` confirms stability and highlights
  runtime bottleneck concentration in fuzz workloads.
- `docs/AUDIT_2026-02-24.md` defines mandatory closeout work before next comprehensive audit.
