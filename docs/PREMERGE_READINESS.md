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

## Current Execution Queue (2026-02-27)

Ordered next implementation targets:

1. **WS-75**: Harden the Python source of truth for production use with stronger operator/runbook, failure-mode, and battle-test evidence on `main`.
2. **WS-77**: Implement the Python SIEM NDJSON/export and ingest-proof workflow informed by the completed WS-76 research.
3. **WS-31 + WS-32**: Start Rust workspace bootstrap + contract canonicalization on the dedicated branch `rust/ws31-bootstrap`, but only after WS-75 and WS-77 are complete.

Current evidence basis:

- `docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md` confirms stability and highlights
  runtime bottleneck concentration in fuzz workloads.
- `docs/AUDIT_2026-02-24.md` defines mandatory closeout work before next comprehensive audit.
- `docs/WS66_EVIDENCE_2026-02-27.md` confirms Python gate cleanliness (`certify`, packaging, dependency audit, SBOM, and short soak with matrix ESR/beta/nightly passing).
- `docs/WS67_SCOPE_PLAN_2026-02-27.md` defines the three bounded merge scopes and their validation floors.
- `docs/WS68_EVIDENCE_2026-02-27.md` confirms Scope A focused regressions and full pytest baseline are green.
- `docs/WS69_EVIDENCE_2026-02-27.md` confirms Scope B runtime/release hardening gates and focused regressions are green.
- `docs/WS70_EVIDENCE_2026-02-27.md` confirms the queue-control and roadmap reconciliation that closes the bounded Python scope sequence.
- `docs/WS71_EVIDENCE_2026-02-27.md` confirms Scope A and Scope B now exist as coherent commit units and records the validation reruns at those commit boundaries.
- `docs/WS72_EVIDENCE_2026-02-27.md` confirms merge-target gates passed on top of the mainline merge candidate and records the Rust handoff branch name.
- `docs/WS74_EVIDENCE_2026-02-27.md` records the Python-first production/siem reprioritization and renewed Rust deferral.
- `docs/WS76_SIEM_READINESS.md` and `docs/WS76_EVIDENCE_2026-02-27.md` capture the vendor-neutral NDJSON contract, Wazuh proof target, and ingest workflow research.
- Latest matrix-soak investigation confirmed prior overnight failures were container bootstrap infrastructure drift, not core Python scan logic; pre-merge hardening must keep those lanes deterministic before Rust branching resumes.
