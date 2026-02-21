# FoxClaw Workslice Plan

This plan converts the current review and research into sequenced, testable execution slices.

## Execution Rules

- Work in strict order unless a slice is marked parallel-safe.
- Every slice must land with tests and doc updates.
- No scan-runtime network access regression is allowed.
- Every changed behavior must be covered by deterministic assertions.

## Slice Queue

| ID | Status | Depends On | Outcome |
| --- | --- | --- | --- |
| WS-01 | complete | none | Intel correlation error paths fail cleanly (no traceback leaks). |
| WS-02 | complete | none | `pref_equals` enforces type-stable semantics. |
| WS-03 | complete | WS-01 | Intel source transport hardening (`https` by default, explicit insecure override). |
| WS-04 | complete | WS-03 | Replace mock extension blocklist with snapshot-backed dataset correlation. |
| WS-05 | complete | none | CI parity with documented local quality gates. |
| WS-06 | complete | WS-05 | Expand policy/rules coverage to current Firefox enterprise policy surface. |
| WS-07 | complete | WS-03 | Add NVD/CVE/KEV adapters and deterministic merge policy. |
| WS-08 | complete | WS-07 | Risk prioritization metadata (KEV-aware baseline, optional EPSS). |
| WS-09 | complete | WS-06, WS-08 | Multi-profile/fleet output contracts and aggregation schema. |
| WS-10 | complete | WS-05 | Release provenance, attestations, and trusted publishing controls. |
| WS-11 | complete | WS-10 | Scheduled dependency vulnerability sweeps and triage workflow. |
| WS-12 | complete | WS-11 | Pre-merge readiness expansion and immediate roadmap planning runbook. |

## Slice Details

### WS-01 - Intel Scan Error Path Hardening

- Status: complete.
- Delivered:
  - `foxclaw/intel/correlation.py` catches malformed `compatibility.ini` parse errors.
  - sqlite query failures are normalized into operational errors.
  - regression tests added in `tests/test_intel_correlation.py`.
- Acceptance: malformed profile/intel store does not emit Python traceback in CLI output.

### WS-02 - Type-Stable Preference Equality

- Status: complete.
- Delivered:
  - `foxclaw/rules/dsl.py` now compares pref values with explicit bool/int separation.
  - regression tests added in `tests/test_rules_m3.py`.
- Acceptance: `True` does not satisfy integer `1`, and `1` does not satisfy boolean `True`.

### WS-03 - Intel Transport Hardening

- Status: complete.
- Goal: eliminate silent plaintext intel ingestion risk.
- Delivered:
  - `intel sync` now blocks plaintext HTTP by default.
  - explicit override `--allow-insecure-http` added for trusted lab mirrors.
  - source manifest metadata includes `transport` and `insecure_transport`.
  - regression coverage added in `tests/test_intel_sync.py` for blocked/allowed paths.
- Acceptance: met.

### WS-04 - Real Extension Blocklist Correlation

- Status: complete.
- Goal: replace static mock blocklist IDs with snapshot-backed evidence.
- Delivered:
  - added source schema support for `foxclaw.mozilla.extension_blocklist.v1`.
  - added `extension_blocklist` SQLite table indexing during `intel sync`.
  - added scan-time offline annotation of extension entries from pinned snapshot data.
  - removed static mock blocklist implementation from `collect`.
  - added regression coverage for sync indexing and scan-time blocklist findings.
- Acceptance: met.

### WS-05 - CI Gate Parity and Enforcement

- Status: complete.
- Goal: align CI with `docs/QUALITY_GATES.md`.
- Delivered:
  - added `quality-gates` job in `.github/workflows/foxclaw-security.yml`.
  - CI now executes lint, typecheck, bandit, vulture, and detect-secrets checks.
  - `scan-balanced` now depends on `quality-gates` in addition to test/integration lanes.
  - workflow documentation updated in `docs/GITHUB_ACTIONS.md`.
- Acceptance: met.

### WS-06 - Policy and Ruleset Coverage Expansion

- Status: complete.
- Goal: keep rules aligned to current Mozilla policy surface.
- Delivered:
  - expanded `balanced` ruleset policy checks for `DisableFirefoxStudies`,
    `ExtensionSettings`, and `HTTPSOnlyMode`.
  - expanded `strict` ruleset with high-severity parity policy checks for the same keys.
  - bumped ruleset versions (`balanced` `0.5.0`, `strict` `0.3.0`).
  - expanded deterministic policy fixtures and integration rules in the testbed generator.
  - added policy-path regression assertions in `tests/test_policies.py` and updated
    integration expected findings in `tests/test_integration_testbed.py`.
- Acceptance: met.

### WS-07 - Multi-Source Vulnerability Enrichment

- Status: complete.
- Goal: extend Mozilla-only intel into deterministic merged correlation.
- Delivered:
  - added deterministic source adapters for:
    - `foxclaw.nvd.cve_records.v1`
    - `foxclaw.cve.list_records.v1`
    - `foxclaw.cisa.known_exploited_vulnerabilities.v1`
  - added SQLite indexing tables for `nvd_cves`, `cve_list_records`, and `kev_catalog`.
  - implemented deterministic severity merge policy:
    - source precedence: `mozilla > nvd > cve_list`.
    - explicit conflict surfacing in finding rationale/evidence.
  - added provenance evidence fields and KEV listing context in correlated findings.
  - added fixtures and regression tests in:
    - `tests/test_intel_sync.py`
    - `tests/test_intel_correlation.py`
- Acceptance: met.

### WS-08 - Prioritization Metadata

- Status: complete.
- Goal: improve triage quality without scan nondeterminism.
- Delivered:
  - added optional EPSS source ingestion via `foxclaw.epss.scores.v1`.
  - added `epss_scores` SQLite indexing table in the sync store.
  - added deterministic risk-priority resolution for intel findings:
    - base priority from selected severity.
    - KEV listing uplift to `critical`.
    - EPSS bucket-based uplift (`>=0.9` very high, `>=0.7` high).
  - exposed `risk_priority` and `risk_factors` on finding records in JSON output.
  - exposed risk metadata in SARIF result properties (`riskPriority`, `riskFactors`).
  - added regression coverage in `tests/test_intel_sync.py`,
    `tests/test_intel_correlation.py`, and `tests/test_sarif_m4.py`.
- Acceptance: met.

### WS-09 - Fleet and Aggregation Contracts

- Status: complete.
- Goal: enable multi-profile and fleet workflows.
- Delivered:
  - added `fleet aggregate` CLI workflow for deterministic multi-profile scans.
  - added normalized fleet contract models in `foxclaw/models.py`:
    - host metadata + deterministic `host_id`.
    - deterministic profile identities (`profile_uid`) and per-profile summaries.
    - flattened `finding_records` for SIEM/fleet ingestion.
    - fleet-level aggregate counters and unique rule-id index.
  - added deterministic fleet report builder/renderer in `foxclaw/report/fleet.py`.
  - added regression coverage:
    - `tests/test_fleet_aggregation.py`
    - merged multi-profile integration contract assertions in
      `tests/test_integration_testbed.py`.
  - documented schema and versioning policy in `docs/FLEET_OUTPUT.md`.
- Acceptance: met.

### WS-10 - Supply-Chain and Release Integrity

- Status: complete.
- Goal: make distribution and build lineage verifiable.
- Delivered:
  - added PR dependency policy gate in `.github/workflows/foxclaw-security.yml`:
    - `dependency-policy` runs `actions/dependency-review-action`.
    - fails PRs on high-severity dependency advisories.
    - required before `scan-balanced`.
  - added release provenance workflow in `.github/workflows/foxclaw-release.yml`:
    - build/dist job verifies release tag matches project version.
    - package artifacts are built + validated (`build`, `twine check`).
    - provenance attestations generated via `actions/attest-build-provenance`.
    - PyPI publish uses OIDC trusted publishing (`pypa/gh-action-pypi-publish`).
    - release assets include built distributions plus `provenance.txt` pointers.
  - published verification runbook in `docs/RELEASE_PROVENANCE.md`.
  - documented workflow behavior updates in `docs/GITHUB_ACTIONS.md`.
- Acceptance: met.

### WS-11 - Scheduled Dependency Vulnerability Sweeps

- Status: complete.
- Goal: continuously detect vulnerable dependency versions between release cycles.
- Delivered:
  - added scheduled dependency-audit workflow in
    `.github/workflows/foxclaw-dependency-audit.yml`:
    - weekly + manual triggers.
    - installs `pip-audit` and runs environment audit.
    - emits `pip-audit.json` artifact.
    - fails on vulnerability findings.
  - added local audit script `scripts/dependency_audit.sh`.
  - added local Make shortcut `make dep-audit`.
  - published runbook in `docs/DEPENDENCY_AUDIT.md`.
  - updated CI/roadmap docs in:
    - `docs/GITHUB_ACTIONS.md`
    - `docs/QUALITY_GATES.md`
    - `docs/ROADMAP.md`
- Acceptance: met.

### WS-12 - Pre-Merge Readiness Expansion

- Status: complete.
- Goal: enforce merge-hold discipline with explicit expanded checks and near-term execution planning.
- Delivered:
  - added pre-merge runbook `docs/PREMERGE_READINESS.md` including:
    - required extended gate sequence (`certify`, `certify-live`, `dep-audit`, packaging dry-run).
    - merge hold criteria.
    - immediate ordered planning queue.
  - updated gate/development docs to reference expanded merge checks:
    - `docs/QUALITY_GATES.md`
    - `docs/DEVELOPMENT.md`
    - `docs/ROADMAP.md`
    - `README.md` docs map.
- Acceptance: met.

## Workslice Update Protocol

- On every slice completion:
  - set status to `complete`,
  - append shipped behavior under that slice,
  - link tests/docs changed,
  - record any follow-on slice split or reprioritization.
