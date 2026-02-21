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
| WS-13 | complete | WS-12 | Ruleset trust boundary with manifest pinning and signature verification. |
| WS-14 | complete | WS-04, WS-07 | Extension reputation depth from AMO intelligence snapshots and policy signals. |
| WS-15 | complete | WS-10 | Release SBOM generation, validation, and artifact publication controls. |
| WS-16 | complete | WS-13 | Trust manifest key rotation and multi-signature threshold policy (`schema_version` `1.1.0`). |
| WS-17 | complete | WS-16 | Source-backed profile fidelity spec and realism validator. |
| WS-18 | complete | WS-17 | AMO-backed extension catalog pipeline with pinned snapshots. |
| WS-19 | complete | WS-17 | Bootstrap-first profile generator from Firefox-created baselines. |
| WS-20 | complete | WS-18, WS-19 | Real-world scenario library with weighted archetypes. |
| WS-21 | complete | WS-20 | Controlled mutation engine with reproducible corruption operators. |
| WS-22 | complete | WS-21 | Runtime fidelity gate and realism scoring for generated profiles. |
| WS-23 | complete | WS-22 | Soak/CI integration with fixed-seed smoke and rotating-seed deep runs. |
| WS-24 | complete | none | Optional `live` workflow wrapper orchestrating `sync` and pinned `scan`. |
| WS-25 | complete | none | Suppression governance (approval workflow metadata + stronger reporting). |
| WS-26 | complete | WS-16 | External ruleset bundle distribution model with managed key delivery. |

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
  - bumped ruleset versions (`balanced` `0.6.0`, `strict` `0.4.0`).
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

### WS-13 - Ruleset Trust Boundary

- Status: complete.
- Goal: fail closed when the configured ruleset does not match expected trusted material.
- Delivered:
  - added trust verification module `foxclaw/rules/trust.py` with:
    - schema-validated trust manifests (`schema_version` `1.0.0`).
    - SHA256 ruleset digest pin validation.
    - optional Ed25519 detached signature verification.
    - explicit fail-closed errors for manifest/digest/signature/key mismatch.
  - added CLI trust controls for both single-profile and fleet workflows:
    - `scan --ruleset-trust-manifest`
    - `scan --require-ruleset-signatures`
    - `fleet aggregate --ruleset-trust-manifest`
    - `fleet aggregate --require-ruleset-signatures`
  - added regression coverage in:
    - `tests/test_ruleset_trust.py`
    - `tests/test_ruleset_trust_cli.py`
    - integration trust-path assertions in `tests/test_integration_testbed.py`
  - added operational hardening checks:
    - `scripts/trust_scan_smoke.sh` for positive + fail-closed CLI trust verification.
    - `scripts/certify.sh` now runs trust smoke as a required gate.
    - `scripts/soak_runner.sh` now runs trust smoke once per cycle.
  - added high-memory fuzz presets for pre-soak burn-in:
    - `make soak-smoke-fuzz1000`
    - `make soak-daytime-fuzz1000`
  - updated architecture/security/roadmap/operator docs:
    - `README.md`
    - `docs/ARCHITECTURE.md`
    - `docs/SECURITY_MODEL.md`
    - `docs/ROADMAP.md`
    - `docs/PREMERGE_READINESS.md`
    - `docs/RULESET_TRUST.md`
- Acceptance: met.

### WS-14 - Extension Intelligence Reputation Depth

- Status: complete.
- Goal: extend extension posture checks with deterministic AMO reputation intelligence.
- Delivered:
  - added source schema support for `foxclaw.amo.extension_intel.v1`.
  - added SQLite indexing table `amo_extension_intel` during `intel sync`.
  - added offline scan-time extension reputation annotation from pinned snapshots:
    - source/reference metadata.
    - reputation level and AMO listing/review/user counts.
  - expanded extension data/report surfaces:
    - new extension intel fields in `foxclaw/models.py`.
    - text report posture column for intel reputation/listed status.
  - added deterministic DSL operator `extension_intel_reputation_absent`.
  - added ruleset coverage:
    - `balanced` rule `FC-EXT-004`.
    - `strict` rule `FC-STRICT-EXT-005`.
  - added regression coverage:
    - `tests/test_intel_sync.py`
    - `tests/test_intel_correlation.py`
    - `tests/test_extensions.py`
    - fixture `tests/fixtures/intel/amo_extension_intel.v1.json`
- Acceptance: met.

### WS-15 - Release SBOM Contract

- Status: complete.
- Goal: publish verifiable SBOM artifacts with release outputs.
- Delivered:
  - added SBOM validation helpers in `foxclaw/release/sbom.py`.
  - added operational scripts:
    - `scripts/generate_sbom.sh`
    - `scripts/verify_sbom.py`
  - added Make targets:
    - `make sbom`
    - `make sbom-verify`
  - updated release workflow `.github/workflows/foxclaw-release.yml`:
    - generate and verify `sbom.cyclonedx.json`.
    - include SBOM in artifact bundle, attest subject paths, and release uploads.
    - include SBOM pointer in `provenance.txt`.
  - added regression coverage in `tests/test_sbom.py`.
  - documented operator workflow in:
    - `docs/SBOM.md`
    - `docs/GITHUB_ACTIONS.md`
    - `docs/RELEASE_PROVENANCE.md`
- Acceptance: met.

### WS-16 - Trust Rotation and Signature Threshold Policy

- Status: complete.
- Goal: support key rollover and explicit signature quorum policy while remaining fail-closed.
- Delivered:
  - extended trust manifest support to `schema_version` `1.1.0` while preserving `1.0.0`.
  - added key lifecycle fields:
    - `status` (`active`, `deprecated`, `revoked`)
    - `valid_from`
    - `valid_to`
  - added per-ruleset threshold control:
    - `min_valid_signatures`
    - required valid signatures computed as `max(1, min_valid_signatures)` when signatures exist.
  - added validation and fail-closed checks for:
    - revoked keys,
    - keys outside validity windows,
    - threshold mismatch and missing signatures under threshold policy.
  - expanded regression coverage:
    - `tests/test_ruleset_trust.py`
    - `tests/test_ruleset_trust_cli.py`
  - hardened trust-cli output checks to avoid false failures from wrapped console output.
- updated trust policy documentation in `docs/RULESET_TRUST.md`.
- Acceptance: met.

### WS-17 - Profile Fidelity Spec and Validator

- Status: complete.
- Delivered:
  - added source-backed profile fidelity contract in `docs/PROFILE_FIDELITY_SPEC.md`.
  - added executable realism gate `scripts/profile_fidelity_check.py`.
  - added regression coverage in `tests/test_profile_fidelity_check_script.py`.
- Acceptance: met.

### WS-18 - AMO Extension Catalog Snapshot Pipeline

- Status: complete.
- Delivered:
  - added catalog builder `scripts/build_extension_catalog.py`.
  - added `make extension-catalog` target for pinned snapshot generation.
  - catalog schema is consumed by profile generators via `--catalog-path`.
- Acceptance: met.

### WS-19 - Bootstrap-First Synth Generator

- Status: complete.
- Delivered:
  - refactored synth generation into realistic artifact scaffolding using
    `scripts/profile_generation_common.py`.
  - added synth modes (`realistic`, `bootstrap`) and deterministic `--seed`.
  - added advanced realism layers:
    - NSS stores (`key4.db`, `cert9.db`, `pkcs11.txt`)
    - HSTS state (`SiteSecurityServiceState.txt`)
    - web storage footprints (`storage/default`)
    - favicon store (`favicons.sqlite`)
  - added metadata provenance per profile (`metadata.json`).
- Acceptance: met.

### WS-20 - Real-World Scenario Library

- Status: complete.
- Delivered:
  - added weighted scenario model:
    - `consumer_default`
    - `privacy_hardened`
    - `enterprise_managed`
    - `developer_heavy`
    - `compromised`
  - scenario selection supports deterministic auto-weighting and forced scenario mode.
  - scenario metadata is persisted in generated profile provenance.
- Acceptance: met.

### WS-21 - Controlled Mutation Engine

- Status: complete.
- Delivered:
  - added bounded mutation operators with severity controls in
    `scripts/profile_generation_common.py`.
  - added mutation controls to both generators:
    - `--mutation-budget`
    - `--max-mutation-severity`
  - fuzz `chaos` mode adds additional deterministic noise operators.
- Acceptance: met.

### WS-22 - Runtime Fidelity Gate

- Status: complete.
- Delivered:
  - integrated fidelity gate into:
    - `scripts/synth_runner.sh`
    - `scripts/fuzz_runner.sh`
  - added enforceable minimum score controls:
    - `--fidelity-min-score`
  - runners now emit average realism score and provenance details.
- Acceptance: met.

### WS-23 - Soak/CI Integration

- Status: complete.
- Delivered:
  - expanded soak orchestration options in `scripts/soak_runner.sh` for
    synth/fuzz mode, seeds, mutation budgets, and fidelity thresholds.
  - updated soak make targets to use deterministic seeds and explicit realism controls.
  - added docs and verification coverage:
    - `docs/SOAK.md`
    - `docs/DEVELOPMENT.md`
    - `tests/test_profile_generation_scripts.py`
    - `docs/PROFILE_HANDOFF.md`
    - `docs/PROFILE_REVIEW_CHECKLIST.md`
- Acceptance: met.

### WS-24 - Optional Live Workflow Wrapper

- Status: complete.
- Goal: provide a one-click orchestrated sync-then-scan workflow without breaking offline-by-default isolation.
- Delivered:
  - Added public architecture spec to `docs/WS24_LIVE_WORKFLOW_ARCHITECTURE.md`.
  - Added new `live` Typer command in `foxclaw/cli.py` that sequences `sync_sources()` and `run_scan()`.
  - The live wrapper captures the exact `snapshot_id` generated during the sync and passes it to the scan phase for deterministic replayability.
  - Generates explicit `[green]Sync successful. Snapshot pinned: <hash>[/green]` provenance in stdout.
  - Fails safely closed without scanning if the network fetch fails.
  - Added integration tests covering successful execution and fallback abort paths in `tests/test_live_orchestration.py`.
- Acceptance: met.

### WS-25 - Suppression Governance

- Status: complete.
- Goal: upgrade suppressions to include approval workflow metadata and stronger tracking.
- Delivered:
  - Bumped policy schema to `1.1.0` and introduced `SuppressionApproval` tracing struct.
  - Added tight fail-closed UTC validation boundary checks tracking timestamp chronologies (`requested_at` <= `approved_at` < `expires_at`).
  - Implemented `foxclaw suppression audit` CLI endpoint to scan policies without invoking the whole engine.
  - Aggregated reporting metrics dynamically to text outputs: expiring soon, legacy usage, active approvers.
  - Upgraded docs (`SUPPRESSIONS.md`) safely.
- Acceptance: met.

### WS-26 - External Ruleset Bundle Distribution

- Status: complete.
- Goal: fetch external ruleset bundles from the network safely utilizing offline-by-default runtime boundaries.
- Delivered:
  - Modeled `RulesetBundleManifest` linking a trusted `KeyringManifest` system (`foxclaw.rules.keyring`).
  - Added network-fetching operations strictly confined to `foxclaw bundle fetch/install/verify` commands.
  - Runtime extraction injects `BundleProvenance` to the local scanner, propagating transparently into SARIF and JSON artifacts.
  - Built full downgrade attack and invalid signature protections natively into the bundle manifest parsing.
- Acceptance: met.

## Workslice Update Protocol

- On every slice completion:
  - set status to `complete`,
  - append shipped behavior under that slice,
  - link tests/docs changed,
  - record any follow-on slice split or reprioritization.
