# Roadmap Normalization (2026-02-26)

## Baseline Reality
- Canonical strategy is `docs/ROADMAP.md` (`docs/ROADMAP.md:87-117`, `docs/ROADMAP.md:139-143`).
- Canonical execution status is `docs/WORKSLICES.md` (`docs/WORKSLICES.md:74-93`, `docs/WORKSLICES.md:836-845`).
- Current state from code and docs:
  - WS-57..64 complete (`docs/WORKSLICES.md:86-93`, `docs/WORKSLICES.md:836-845`).
  - Learning metadata and HSTS/doc drift fixes already landed (`foxclaw/cli.py:415-421`, `foxclaw/learning/history.py:151-175`, `foxclaw/collect/artifacts.py:16-21`, `docs/PREMERGE_READINESS.md:62-70`).

## Remaining Mismatches (Docs vs Runtime/Planning)
1. WS-64 evidence is complete; keep it attached to release-track PRs and future audit packets (`docs/WS64_EVIDENCE_2026-02-26.md`, `docs/WORKSLICES.md:836-845`).
2. Roadmap draft is archived; ensure references continue to point to canonical roadmap/workslices (`docs/archive/roadmap/ROADMAP_UPDATE_2026_DRAFT.md`, `docs/ROADMAP.md:91-103`, `docs/WORKSLICES.md:12-20`).

## Unified Ordered Execution Plan With Gates

### Gate G1: WS-55B Deterministic Trend/Novelty
- Scope: trend and novelty enrichment built on append-only WS-55A store.
- Dependency: WS-55A complete (`docs/WORKSLICES.md:83-84`).

### Gate G2: WS-56 Fleet Prevalence
- Scope: fleet prevalence/correlation fields after WS-55B proves stable.
- Dependency: WS-56 depends on WS-55B and WS-09 (`docs/WORKSLICES.md:85`).

### Gate G3: Threat-Surface Expansion (WS-47..WS-54)
- Scope: handlers/cert/pkcs11/session/search/cookie/HSTS + CVE simulation.
- Evidence: pending slice set (`docs/WORKSLICES.md:75-82`).

### Gate G4: Rust Contract Bootstrap (WS-31 + WS-32)
- Scope: rust workspace + contract canonicalization.
- Evidence: pending slices (`docs/WORKSLICES.md:60-61`).

## Definition of Done (Near-Term Slices)

### WS-64
- Code DoD:
  - no unresolved contract mismatches in runtime/docs for exit codes, artifact naming, lock/UNC behavior.
- Test DoD:
  - `./scripts/certify.sh`
  - `pytest -q`
  - `python -m foxclaw acquire windows-share-batch --source-root /tmp/foxclaw-ws64-source --staging-root /tmp/foxclaw-ws64-stage --out-root /tmp/foxclaw-ws64-out --max 3 --workers 1 --treat-high-findings-as-success`
- Docs DoD:
  - `docs/WORKSLICES.md` WS-64 marked complete with evidence links.

### WS-55B
- Code DoD:
  - deterministic per-rule trend and novelty computation from history DB.
- Test DoD:
  - deterministic replay tests (same DB/input => identical output).
  - `pytest -q tests/test_scan_history.py tests/test_determinism.py`.
- Docs DoD:
  - update `docs/SCAN_LEARNING_LOOP.md` and `docs/WORKSLICES.md` with final field semantics.

### WS-56
- Code DoD:
  - fleet prevalence fields added without changing current field semantics.
- Test DoD:
  - `pytest -q tests/test_fleet_aggregation.py tests/test_integration_testbed.py` plus WS-56 tests.
- Docs DoD:
  - `docs/FLEET_OUTPUT.md` schema section updated and versioned.

## 2-Week Plan

### Week 1: Begin G1 (WS-55B)
- Tasks:
  - implement deterministic trend/novelty schema and core logic,
  - keep roadmap references canonical (no draft-based planning),
  - lock doc contracts in canonical locations.
- Risks:
  - accidental enrichment coupling into rule-evaluation path.
- Acceptance tests:
  - `pytest -q tests/test_scan_history.py tests/test_determinism.py`
  - `./scripts/certify.sh`

### Week 2: Continue G1 and prepare G2
- Tasks:
  - finish WS-55B and start WS-56 schema preparation.
- Risks:
  - schema growth without strong versioning discipline.
- Acceptance tests:
  - `pytest -q tests/test_scan_history.py tests/test_determinism.py`
  - `./scripts/certify.sh`

## 6-Week Plan

### Weeks 1-2
- Sustain WS-64 closure evidence and launch WS-55B.

### Weeks 3-4
- Finish WS-55B implementation and docs.
- Acceptance:
  - deterministic replay test suite green,
  - full certify suite green.

### Weeks 5-6
- Land WS-56 and start WS-47 as first threat-surface cut.
- Acceptance:
  - `pytest -q tests/test_fleet_aggregation.py tests/test_integration_testbed.py` + new WS-47 tests,
  - docs merged in same PRs as code changes.
