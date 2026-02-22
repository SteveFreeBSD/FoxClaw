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

## Immediate Planning Queue (Post-WS31)

Ordered next implementation targets:

1. **WS-32**: Contract canonicalization for migration (freeze JSON/SARIF compatibility policy and publish migration fixtures).
2. **WS-35**: Cross-OS profile corpus expansion for parser/fidelity stress and migration parity.
3. **WS-36**: Rust runtime skeleton and crate boundary formalization (`model`, `collect`, `rules`, `report`, `cli`).
