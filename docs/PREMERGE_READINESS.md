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

## Merge Hold Criteria

Do not merge when any of the following is true:

- any required gate fails.
- fixture drift is present and not intentionally committed.
- docs are out of sync with CLI/workflow/schema surfaces.
- release tag/version plan is unresolved.

## Immediate Planning Queue (Post-WS11)

Ordered next implementation targets:

1. Signed policy-pack verification boundary (Phase 2).
2. Extension intelligence correlation depth (AMO/reputation expansion).
3. Release SBOM artifact generation and verification guidance.
