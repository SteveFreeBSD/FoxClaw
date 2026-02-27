# FoxClaw Workslice Plan

This plan converts the current review and research into sequenced, testable execution slices.

## Execution Rules

- Work in strict order unless a slice is marked parallel-safe.
- Every slice must land with tests and doc updates.
- No scan-runtime network access regression is allowed.
- Every changed behavior must be covered by deterministic assertions.

## Current Direction (2026-02-27)

- Latest deep soak baseline is documented in:
  - `docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md`
- Latest comprehensive repo audit is documented in:
  - `docs/AUDIT_2026-02-24.md`
- Immediate execution focus:
  - WS-31 (on dedicated branch `rust/ws31-bootstrap`)
- Rationale:
  - The validated Python baseline is now merged cleanly and all merge-target gates passed on the merge candidate.
  - `main` remains the clean Python source of truth.
  - Rust bootstrap resumes next, but only on the dedicated branch `rust/ws31-bootstrap` seeded from merged `main`.

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
| WS-27 | skipped | none | Scrapped CEL/OPA expansion to keep ruleset DSL strictly declarative for future Rust port. |
| WS-28 | complete | WS-17 | Profile realism deferred hardening (Firefox launch sanity gate + cross-OS baselines). |
| WS-29 | complete | WS-26 | Refresh planning docs with post-WS26 queue (`PREMERGE_READINESS.md` + `WORKSLICES.md`). |
| WS-30 | complete | WS-28 | Schema lockdown (validate JSON/SARIF schemas for 1:1 Rust parity tests). |
| WS-31 | pending | WS-30 | Initialize `foxclaw-rs` Rust workspace and integration testbed runner. |
| WS-32 | pending | WS-30 | Contract canonicalization: freeze JSON/SARIF compatibility policy and publish migration fixtures. |
| WS-33 | pending | WS-32 | ATT&CK mapping layer for browser-focused findings with deterministic evidence fields. |
| WS-34 | pending | WS-26, WS-32 | Trusted update chain for intel/rules (signed metadata, freshness checks, rollback resistance). |
| WS-35 | pending | WS-28, WS-46 | Cross-OS profile corpus expansion for parser/fidelity stress and migration parity. |
| WS-36 | pending | WS-31 | Formalize Rust crate boundaries and core runtime skeleton (`model`, `collect`, `rules`, `report`, `cli`). |
| WS-37 | pending | WS-32, WS-36 | Rust contract models + serializers with schema validation parity. |
| WS-38 | pending | WS-35, WS-37 | Port high-risk profile parsers to Rust (`prefs.js`, extensions metadata, SQLite/NSS artifacts). |
| WS-39 | pending | WS-38 | Port declarative rules DSL evaluator to Rust with deterministic parity assertions. |
| WS-40 | pending | WS-39 | Differential Python-vs-Rust CI gate and mismatch classification workflow. |
| WS-41 | pending | WS-09, WS-32 | OCSF-aligned export profile and fleet aggregation contract validation. |
| WS-42 | pending | WS-36 | Rust dependency/trust gates in CI (`cargo-audit`, `cargo-deny`, `cargo-vet`). |
| WS-43 | pending | WS-34 | Signed intel/rules distribution hardening in runtime install/update flows. |
| WS-44 | pending | WS-40, WS-43 | Shadow-mode rollout for Rust engine with parity, reliability, and SLO thresholds. |
| WS-45 | pending | WS-44 | Make Rust the default runtime and deprecate Python fallback path. |
| WS-46 | complete | WS-28 | Enterprise Windows-share profile acquisition lane with deterministic local staging scans. |
| WS-47 | complete | WS-30 | Protocol handler hijack detection (`handlers.json` parsing, executable path flags). |
| WS-48 | complete | WS-30 | NSS certificate store audit (`cert9.db` rogue root CA detection). |
| WS-49 | complete | WS-30 | PKCS#11 module injection detection (`pkcs11.txt` non-Mozilla path validation). |
| WS-50 | complete | WS-30 | Session restore data exposure (`sessionstore.jsonlz4` sensitive data detection). |
| WS-51 | complete | WS-30 | Search engine integrity (`search.json.mozlz4` default engine validation). |
| WS-52 | complete | WS-30 | Cookie security posture (`cookies.sqlite` session theft signals). |
| WS-53 | complete | WS-30 | HSTS state integrity (`SiteSecurityServiceState.txt` downgrade detection; `.bin` accepted for legacy captures). |
| WS-54 | complete | WS-47, WS-48, WS-49, WS-50, WS-51, WS-52, WS-53 | CVE advisory simulation scenarios in Windows and Python profile generators. |
| WS-55A | complete | WS-54 | Scan-history ingestion: append-only local SQLite store + deterministic learning artifact. |
| WS-55B | complete | WS-55A | Per-rule trend/novelty analysis from history snapshots. |
| WS-56 | complete | WS-55B, WS-09 | Fleet-wide pattern correlation and finding prevalence enrichment. |
| WS-57 | complete | none | Restore quality gate health (`ruff`, `detect-secrets`) to unblock reliable merge validation. |
| WS-58 | complete | WS-57 | Enforce exit-code contract conformance for operational errors vs high-signal scan outcomes. |
| WS-59 | complete | WS-58 | Align UNC fail-closed and lock-marker checks across `scan`, `live`, discovery, and acquire paths. |
| WS-60 | complete | WS-58 | Correct learning-store determinism and metadata extraction logic with regression tests. |
| WS-61 | complete | WS-58, WS-59, WS-60 | Synchronize docs with runtime behavior (exit codes, lock markers, artifact names, WS status). |
| WS-62 | complete | WS-59 | Reduce duplicated helpers/constants without behavior drift. |
| WS-63 | complete | WS-61 | Resolve low-risk CLI/API polish items (`writeable` strategy, policy-path error wording, trust helper API boundaries). |
| WS-64 | complete | WS-57, WS-58, WS-59, WS-60, WS-61, WS-62, WS-63 | Audit-readiness gate: full checks + windows-share mini soak + zero open critical/high audit findings. |
| WS-65 | complete | WS-64 | Source-of-truth reconciliation: restore Python as the canonical merge target, defer Rust bootstrap to a dedicated branch, and realign planning docs. |
| WS-66 | complete | WS-65 | Python pre-merge hardening: rerun certify/package/security gates, short soak confidence pass, review evidence, and merge only when Python is clean. |
| WS-67 | complete | WS-66 | Isolate mixed in-flight changes into coherent review scopes and prepare the Python baseline for merge without dragging unrelated work across the boundary. |
| WS-68 | complete | WS-67 | Scope A merge pack: land threat-surface expansion and generator parity changes as a bounded Python feature block. |
| WS-69 | complete | WS-67 | Scope B merge pack: land matrix/runtime/release hardening changes needed to keep the Python baseline operationally clean. |
| WS-70 | complete | WS-67, WS-68, WS-69 | Scope C merge pack: land docs, evidence, and queue-control updates after the bounded Python scopes are merged. |
| WS-71 | complete | WS-68, WS-69, WS-70 | Python merge execution checkpoint: convert the validated scope packs into coherent commit/merge units and keep Rust branch work blocked until the Python baseline lands cleanly. |
| WS-72 | complete | WS-71 | Python mainline merge and Rust branch handoff: merge the validated Python baseline to mainline, rerun merge-target gates, and only then cut the dedicated Rust branch at WS-31/WS-32. |

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
  - Preserved compatibility for `1.0.0` policy files (default when `schema_version` is omitted) while enforcing approval requirements for explicit `1.1.0` files.
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

### WS-27 - Policy Language Expansion Spike

- Status: skipped.
- Goal: explore CEL/OPA behind strict engine interfaces for flexible rule authoring.
- Outcome: Scrapped. Integrating a heavy Python-native policy engine (like OPA/Rego) conflicts with the strategic goal of porting FoxClaw to a high-performance Rust single-binary appliance. The ruleset DSL will remain strictly declarative (JSON/YAML) to ensure 1:1 parity during the Rust migration.

### WS-28 - Profile Realism Deferred Hardening

- Status: complete.
- Goal: implement the deferred Firefox launch sanity gate and expand cross-OS baseline supports.
- Delivered:
  - Created `scripts/profile_launch_gate.py` to assert synthetic profile survival in a live headless engine.
  - Added launch gate arguments to `scripts/synth_runner.sh`, `scripts/fuzz_runner.sh`, and `scripts/soak_runner.sh`.
  - Enforced launch-gate behavior with explicit non-zero exits when `--enforce` is used and Firefox is unavailable.
  - Added `make profile-launch-gate` and wired `--require-launch-gate` into overnight soak smoke targets.
  - Hardened runner argument handling and validation for launch-gate score propagation in soak/synth/fuzz paths.
  - Fixed container smoke/demo scan invocations to use explicit ruleset/policy inputs and deterministic output mode.
  - Added launch-gate regression coverage in `tests/test_profile_launch_gate_script.py` (pass path, enforced missing-Firefox path, and destructive launch behavior).
- Acceptance: met.

### WS-29 - Refresh Planning Docs with Post-WS26 Queue

- Status: complete.
- Goal: update runbooks and work tracking to align with newest roadmap stops.
- Delivered:
  - Updated `docs/PREMERGE_READINESS.md`.
  - Added WS-27 through WS-31 to `docs/WORKSLICES.md`.
- Acceptance: met.

### WS-30 - Schema Lockdown (Rust Migration Prep)

- Status: complete.
- Goal: enforce strict schema validation on all JSON and SARIF outputs to guarantee byte-for-byte fidelity when porting to Rust.
- Delivered:
  - Added hidden deterministic parity option (`--deterministic`) for `scan` and `live` CLI paths to freeze `generated_at` for contract comparisons.
  - Added deterministic SARIF path normalization in `foxclaw/report/sarif.py` to prevent host-path leakage from breaking parity fixtures.
  - Added regression coverage in `tests/test_determinism.py` to assert byte-stable JSON/SARIF outputs across repeated runs.
  - Updated deterministic fixture/container scan scripts to exercise locked-output behavior in operational gates.
  - Validated full quality gates and mini-soak stability:
    - `make verify-full`
    - `scripts/soak_runner.sh --duration-hours 1 --max-cycles 1 --integration-runs 1 --snapshot-runs 1 --synth-count 4 --synth-mode bootstrap --synth-seed 424242 --synth-mutation-budget 0 --synth-fidelity-min-score 70 --require-launch-gate --launch-gate-min-score 50 --fuzz-count 4 --fuzz-mode chaos --fuzz-seed 525252 --fuzz-mutation-budget 3 --fuzz-fidelity-min-score 50 --matrix-runs 0 --label mini-pre-ws31`
  - Re-validated gates after launch-gate test hardening on 2026-02-22:
    - `make verify-full`
    - `scripts/soak_runner.sh --duration-hours 1 --max-cycles 1 --integration-runs 1 --snapshot-runs 1 --synth-count 4 --synth-mode bootstrap --synth-seed 424242 --synth-mutation-budget 0 --synth-fidelity-min-score 70 --require-launch-gate --launch-gate-min-score 50 --fuzz-count 4 --fuzz-mode chaos --fuzz-seed 525252 --fuzz-mutation-budget 3 --fuzz-fidelity-min-score 50 --matrix-runs 0 --label mini-post-hardening`
- Acceptance: met.

### WS-31 - Initialize Rust Backend

- Status: pending.
- Goal: instantiate the `foxclaw-rs` Cargo workspace and build the integration testbed runner that asserts Rust output parity against Python fixtures.
- Execution note: deferred from mainline execution until WS-66 completes and a dedicated Rust branch is cut from the validated Python baseline.

### WS-32 - Contract Canonicalization for Migration

- Status: pending.
- Goal: freeze JSON/SARIF compatibility policy and publish canonical migration fixtures that both engines must satisfy.
- Execution note: resume only after WS-31 begins on the dedicated Rust branch.

### WS-46 - Enterprise Windows-Share Profile Acquisition Lane

- Status: complete.
- Goal: support enterprise remote-profile workflows by staging Firefox profiles from Windows shares into deterministic local snapshots before scanning.
- Delivered:
  - Added source-backed research and tactical guidance in:
    - `docs/RESEARCH_2026-02-22_WINDOWS_SHARE_AUDIT.md`
    - `docs/WINDOWS_SHARE_TESTING.md`
  - Added deterministic staging + scan automation script:
    - `scripts/windows_share_scan.py`
  - Promoted lane into first-class CLI integration:
    - `foxclaw scan` (auto-stage for share-hosted profile paths)
    - `foxclaw acquire windows-share-scan`
    - `foxclaw acquire windows-share-batch`
    - implementation entrypoint: `foxclaw/acquire/windows_share.py`
  - Workflow behavior:
    - copies profile from share/mount path into local staging snapshot,
    - fails closed on active profile lock markers unless explicitly overridden,
    - strips write bits from staged files by default,
    - emits JSON/SARIF/snapshot outputs and `stage-manifest.json` provenance metadata,
    - propagates scan exit codes (`0`, `2`) by default so vulnerability findings remain automation-visible.
  - Added regression coverage in `tests/test_windows_share_scan_script.py` for:
    - successful staged scan path with passthrough `foxclaw` exit code `2`,
    - optional `--treat-high-findings-as-success` normalization path,
    - lock-marker fail-closed behavior,
    - explicit lock-marker override path.
  - Added CLI coverage in `tests/test_acquire_windows_share_cli.py` for:
    - CLI wrapper passthrough semantics and lock-marker controls,
    - mounted-share path workflow,
    - real end-to-end HIGH finding detection through staged scan.
  - Updated doc surfaces:
    - `README.md`
    - `docs/TESTBED.md`
    - `docs/ROADMAP.md`
    - `docs/WORKSLICES.md`
- Validation evidence:
  - `pytest -q tests/test_windows_share_scan_script.py tests/test_acquire_windows_share_cli.py`
- Acceptance: met.

### WS-33 - ATT&CK Mapping for Browser Findings

- Status: pending.
- Goal: map relevant finding classes to ATT&CK techniques (including browser extension abuse and browser credential access) with deterministic evidence semantics.

### WS-34 - Trusted Intel/Rules Update Chain

- Status: pending.
- Goal: harden intel and rules update workflows with signed metadata, freshness windows, and rollback-resistant verification.

### WS-35 - Cross-OS Profile Corpus Expansion

- Status: pending.
- Goal: grow deterministic Windows/macOS/Linux profile fixtures and damaged-artifact scenarios for migration stress coverage, building on WS-46 share-staging acquisition workflow.

### WS-36 - Rust Runtime Skeleton and Boundaries

- Status: pending.
- Goal: define crate boundaries and shared interfaces for the Rust scanner runtime (`model`, `collect`, `rules`, `report`, `cli`).

### WS-37 - Rust Contract Models and Serializers

- Status: pending.
- Goal: implement Rust-side contract models/serializers validated against locked JSON/SARIF schemas.

### WS-38 - Rust Parser Port (High-Risk Artifacts)

- Status: pending.
- Goal: port the highest-risk profile artifact parsers to Rust while preserving semantic parity and read-only behavior.

### WS-39 - Rust Declarative Rules Evaluator

- Status: pending.
- Goal: implement the existing declarative rules DSL evaluator in Rust without introducing programmable policy-engine drift.

### WS-40 - Differential CI Gate (Python vs Rust)

- Status: pending.
- Goal: make normalized differential comparisons mandatory in CI and classify every mismatch before merge.

### WS-41 - OCSF Export and Fleet Contract Validation

- Status: pending.
- Goal: add OCSF-aligned export mode and validate fleet aggregation contracts for downstream SIEM/XDR systems.

### WS-42 - Rust Dependency and Trust Gates

- Status: pending.
- Goal: enforce Rust dependency policy and advisory governance in CI via `cargo-audit`, `cargo-deny`, and `cargo-vet`.

### WS-43 - Signed Distribution Hardening

- Status: pending.
- Goal: enforce signed and verifiable intel/rules distribution flows end-to-end in operational install/update paths.

### WS-44 - Rust Shadow-Mode Rollout

- Status: pending.
- Goal: run Rust in production shadow mode with explicit parity, reliability, and performance thresholds before default cutover.

### WS-45 - Rust Default Runtime Cutover

- Status: pending.
- Goal: make Rust the default runtime and retire Python fallback according to deprecation and rollback policy.

### WS-47 - Protocol Handler Hijack Detection

- Status: complete.
- Goal: detect custom protocol handlers in `handlers.json` pointing to local executables that could enable code execution via crafted links.
- Delivered:
  - added `foxclaw/collect/handlers.py` for deterministic protocol-handler hijack parsing from `handlers.json` payloads.
  - extended artifact parsing to record deterministic suspicious handler metadata for `ask=false` handlers targeting local executables (`.exe`, `.bat`, `.ps1`, `.cmd`, `.sh`).
  - added DSL operator `protocol_handler_hijack_absent` for deterministic rule evaluation against handler-hijack evidence.
  - added new rules:
    - `FC-HANDLER-001` in `balanced.yml`.
    - `FC-STRICT-HANDLER-001` in `strict.yml`.
  - expanded deterministic regression coverage in `tests/test_profile_artifacts.py` and `tests/test_rules_m3.py`.
  - ATT&CK mapping: T1204 (User Execution).
- Acceptance: met.

### WS-48 - NSS Certificate Store Audit

- Status: complete.
- Goal: detect rogue or unexpected root CA certificates injected into Firefox's NSS certificate store (`cert9.db`).
- Delivered:
  - added `foxclaw/collect/certificates.py` for deterministic, read-only `cert9.db` root-audit parsing.
  - extended artifact parsing to collect deterministic root-store metadata from `cert9.db`, including suspicious root counts and normalized risk entries.
  - implemented `rogue_root_ca_absent` DSL operator to surface suspicious roots as findings.
  - added new rules:
    - `FC-CERT-001` in `balanced.yml`.
    - `FC-STRICT-CERT-001` in `strict.yml`.
  - added deterministic regression tests for missing/empty/benign/rogue root cases and DSL/artifact integration.
  - ATT&CK mapping: T1553.004 (Install Root Certificate).
- Acceptance: met.

### WS-49 - PKCS#11 Module Injection Detection

- Status: complete.
- Goal: detect PKCS#11 modules registered in `pkcs11.txt` that point to non-Mozilla library paths, which could enable DLL injection into the Firefox process.
- Delivered:
  - added `foxclaw/collect/pkcs11.py` for deterministic `pkcs11.txt` module parsing and non-standard library path classification.
  - extended artifact parsing to include deterministic PKCS#11 metadata (`pkcs11_modules_count`, suspicious module count/details).
  - implemented `pkcs11_module_injection_absent` DSL operator for deterministic finding generation.
  - added new rules:
    - `FC-PKCS11-001` in `balanced.yml`.
    - `FC-STRICT-PKCS11-001` in `strict.yml`.
  - added deterministic regression coverage for missing/benign/suspicious module-path scenarios and DSL/artifact integration.
  - ATT&CK mapping: T1129 (Shared Modules).
- Acceptance: met.

### WS-50 - Session Restore Data Exposure

- Status: complete.
- Goal: detect sensitive form data, authentication tokens, and active session state stored in `sessionstore.jsonlz4` that could enable session replay attacks.
- Delivered:
  - added `foxclaw/collect/session.py` for deterministic session restore payload auditing.
  - added deterministic parsing support for `sessionstore.jsonlz4` with Mozilla LZ4 header awareness and JSON payload handling.
  - added sensitive value detection for password fields, token/auth fields, and credit-card-like values (Luhn validated).
  - added artifact metadata for session restore state and sensitive entry counts/details.
  - implemented `session_restore_sensitive_data_absent` DSL operator and new rules:
    - `FC-SESSION-001` in `balanced.yml`.
    - `FC-STRICT-SESSION-001` in `strict.yml`.
  - added deterministic regression coverage across collector/artifact/DSL paths.
  - ATT&CK mapping: T1005 (Data from Local System), T1185 (Browser Session Hijacking).
- Acceptance: met.

### WS-51 - Search Engine Integrity

- Status: complete.
- Goal: detect search engine hijacking by validating the default search engine in `search.json.mozlz4`.
- Delivered:
  - added `foxclaw/collect/search.py` for deterministic `search.json.mozlz4` parsing with Mozilla LZ4 header awareness.
  - implemented deterministic default-engine extraction and allowlist validation for standard providers.
  - added custom search URL/domain detection for hijack-like default engine changes.
  - extended artifact parsing with search integrity metadata (`default_search_engine_*`, suspicious count/details).
  - implemented `search_engine_hijack_absent` DSL operator and new rules:
    - `FC-SEARCH-001` in `balanced.yml`.
    - `FC-STRICT-SEARCH-001` in `strict.yml`.
  - added deterministic regression coverage for missing/benign/suspicious/invalid payload paths.
  - ATT&CK mapping: T1583.001 (Acquire Infrastructure: Domains).
- Acceptance: met.

### WS-52 - Cookie Security Posture

- Status: complete.
- Goal: detect cookie security weaknesses in `cookies.sqlite` that could enable session theft or tracking.
- Delivered:
  - added `foxclaw/collect/cookies.py` for deterministic read-only `cookies.sqlite` auditing.
  - added cookie posture signal detection for:
    - long-lived cookies (>1 year lifetime from creation timestamp).
    - `SameSite=None` on sensitive/auth-like domains.
    - missing `HttpOnly` on authentication cookie names.
    - excessive third-party tracking cookie volume.
  - extended profile artifact parsing with cookie security metadata and suspicious-entry serialization.
  - implemented `cookie_security_posture_absent` DSL operator and new rules:
    - `FC-COOKIE-001` in `balanced.yml`.
    - `FC-STRICT-COOKIE-001` in `strict.yml`.
  - added deterministic regression coverage across collector/artifact/DSL paths.
  - ATT&CK mapping: T1539 (Steal Web Session Cookie).
- Acceptance: met.

### WS-53 - HSTS State Integrity

- Status: complete.
- Goal: detect HSTS downgrade attacks by validating `SiteSecurityServiceState.txt` for missing or removed entries.
- Delivered:
  - added `foxclaw/collect/hsts.py` for deterministic read-only `SiteSecurityServiceState.txt` parsing and integrity analysis.
  - implemented critical-domain baseline expectation derivation from HTTPS history hosts (`places.sqlite`) for banking/email/corporate identity domains.
  - added missing critical-domain HSTS detection with downgrade/removal signals:
    - missing critical HSTS entries.
    - selective entry deletion pattern (same registrable domain partial removal).
    - truncation pattern (sparse/malformed/truncated state indicators).
  - extended artifact parsing with HSTS integrity metadata and suspicious-entry serialization.
  - implemented `hsts_downgrade_absent` DSL operator and new rules:
    - `FC-HSTS-001` in `balanced.yml`.
    - `FC-STRICT-HSTS-001` in `strict.yml`.
  - added deterministic regression coverage across collector/artifact/DSL paths.
  - ATT&CK mapping: T1557 (Adversary-in-the-Middle).
- Acceptance: met.

### WS-54 - CVE Advisory Simulation Scenarios

- Status: complete.
- Goal: add CVE-inspired adversary scenarios to both the Windows (`mutate_profile.mjs`) and Python (`adversary_profiles.py`) profile generators.
- Delivered:
  - added new CVE advisory scenario names to both generators:
    - `cve_sandbox_escape`, `cve_extension_abuse`, `cve_session_hijack`, `cve_cert_injection`, `cve_handler_hijack`, `cve_hsts_downgrade`, `cve_search_hijack`.
  - Python adversary generator now applies deterministic per-scenario artifact mutations that directly trigger WS-47..WS-53 strict finding IDs and records matched finding IDs in `adversary-summary.json`.
  - Windows mutator now applies deterministic per-scenario artifact mutations for WS-47..WS-53, records expected CVE strict rule IDs in metadata output, and PowerShell `ValidateSet` includes all CVE scenario names.
  - added deterministic round-trip regression coverage:
    - Python adversary generator scenario-to-expected-rule assertions.
    - Windows mutator scenario-to-expected-rule assertions (dependency-aware runtime skip when `better-sqlite3` is unavailable).
- Acceptance: met.

### WS-55 - Adaptive Scan Intelligence (Self-Learning)

- Status: complete (`WS-55A` and `WS-55B` complete).
- Goal: implement a local, deterministic self-learning feedback loop where FoxClaw accumulates scan history and enriches future scan outputs with trend analysis and novelty detection.
- Scope:
  - new module `foxclaw/learning/history.py`: append-only SQLite scan history store.
  - new module `foxclaw/learning/trends.py`: finding trend direction analysis.
  - new module `foxclaw/learning/novel.py`: novelty scoring for first-seen findings.
  - CLI flags: `--history-db`, `--enable-trend-analysis`, `--flag-novel-findings`.
  - output enrichment fields: `trend_direction`, `first_seen_at`, `novelty_score`.
  - constraints: deterministic, offline, append-only, optional enrichment layer.
  - ATT&CK mapping: enriches all existing technique mappings with temporal context.

### WS-56 - Fleet Pattern Correlation

- Status: complete.
- Goal: extend self-learning enrichment to fleet-wide scanning, adding cross-profile pattern correlation and finding prevalence metrics.
- Delivered:
  - extended `foxclaw/learning/history.py` with deterministic latest-snapshot fleet aggregation queries.
  - added `foxclaw/learning/fleet_patterns.py` for deterministic fleet prevalence, outlier elevation, and pairwise Jaccard correlation helpers.
  - learning artifact output now includes `rule_fleet_prevalence` and `fleet_rule_correlations`, including `fleet_prevalence` and outlier priority fields.
  - added deterministic low-prevalence outlier priority elevation (`normal`/`elevated`) using the fleet prevalence threshold.
  - expanded deterministic regression coverage in `tests/test_scan_history.py` for prevalence, latest-snapshot semantics, and cross-profile correlations.
- Acceptance: met.

### WS-57 - Quality Gate Unblock Pack

- Status: complete.
- Goal: reestablish deterministic branch-health validation before functional changes continue.
- Scope:
  - clear `ruff` failures.
  - clear `detect-secrets` failures with stable, reviewed false-positive handling.
  - keep CI/local parity between workflow and `scripts/check_secrets.sh`.

### WS-58 - Exit-Code Contract Conformance

- Status: complete.
- Goal: ensure operational failures never use finding-oriented exit codes.
- Scope:
  - normalize acquire/scan command operational-error returns to `1`.
  - keep high-signal outcomes (`HIGH` findings, drift, governance violations) explicit and documented.
  - add regression coverage for corrected command-level semantics.

### WS-59 - Command Safety Parity (UNC + Lock Markers)

- Status: complete.
- Goal: enforce identical fail-closed path safety semantics across command entrypoints.
- Scope:
  - apply UNC default-deny policy to `live` command path.
  - unify lock marker handling (`parent.lock`, `.parentlock`, `lock`) across scan/discovery/acquire.
  - regression tests for all command surfaces.

### WS-60 - Learning Store Correctness Hardening

- Status: complete.
- Goal: make learning-store behavior match determinism claims and remove ineffective metadata extraction.
- Scope:
  - remove or replace dead `hasattr()` extraction paths.
  - align artifact determinism contract and implementation.
  - extend scan-history tests for deterministic artifact behavior.

### WS-61 - Documentation Contract Synchronization

- Status: complete.
- Goal: eliminate drift between docs, CLI behavior, and collector/runtime implementation.
- Scope:
  - align exit-code semantics language.
  - align lock-marker and UNC behavior documentation.
  - align artifact naming (`SiteSecurityServiceState.txt`, with legacy `.bin` compatibility) and WS status tracking.
  - fix malformed workslice table rows.

### WS-62 - Redundancy Reduction Refactor

- Status: complete.
- Goal: reduce duplicated helpers/constants that create drift risk while preserving behavior.
- Scope:
  - centralize severity ordering helpers.
  - centralize sqlite read-only URI helper.
  - centralize repeated intel sqlite helper patterns.

### WS-63 - Low-Risk API/UX Polish

- Status: complete.
- Goal: close low-severity audit findings that affect operator clarity and long-term compatibility.
- Scope:
  - decide and implement `--keep-stage-writeable` alias/rename policy.
  - clarify policy-path symlink error wording.
  - expose trust helper APIs intentionally instead of cross-module private imports.

### WS-64 - Audit Readiness Gate

- Status: complete.
- Goal: define explicit completion gates before the next comprehensive audit.
- Scope:
  - all WS-57 through WS-63 completed.
  - all quality/security/test gates green.
  - windows-share mini soak passes with stable artifacts and no operational failures.
- Delivered:
  - full quality and security gates green via `./scripts/certify.sh`.
  - full test suite green via `pytest -q` (`199 passed`).
  - windows-share mini soak completed:
    - `python -m foxclaw acquire windows-share-batch --source-root /tmp/foxclaw-ws64-source --staging-root /tmp/foxclaw-ws64-stage --out-root /tmp/foxclaw-ws64-out --max 3 --workers 1 --treat-high-findings-as-success`
    - summary: `attempted=3`, `operational_failure_count=0`.
  - archived evidence note: `docs/WS64_EVIDENCE_2026-02-26.md`.

### WS-65 - Source-of-Truth Reconciliation

- Status: complete.
- Goal: restore Python as the explicit canonical merge target before any Rust bootstrap work resumes.
- Scope:
  - update `Current Direction` to point at Python pre-merge hardening instead of Rust bootstrap.
  - align pre-merge runbook queue with Python-first execution.
  - align roadmap language so Rust starts only after the validated Python baseline is merged from mainline.
- Delivered:
  - updated `docs/WORKSLICES.md` current direction and queue to insert WS-65/WS-66 ahead of WS-31.
  - added explicit deferral notes to WS-31 and WS-32 so Rust work starts on a dedicated branch after Python revalidation.
  - updated `docs/PREMERGE_READINESS.md` and `docs/ROADMAP.md` to remove the Python-vs-Rust execution-order conflict.

### WS-66 - Python Pre-Merge Hardening

- Status: complete.
- Goal: prove the Python implementation is the clean source of truth before any Rust branch work begins.
- Scope:
  - rerun `./scripts/certify.sh`, packaging dry-run, SBOM verification, and dependency audit.
  - run a short soak confidence pass after matrix bootstrap hardening and review any residual failures as product vs infrastructure.
  - verify docs/runtime/test evidence are synchronized and capture merge recommendation with explicit blockers if any gate fails.
- Delivered:
  - repaired pre-merge gate blockers uncovered during the run:
    - `ruff` import ordering drift in WS-47..WS-53 collector/test files,
    - `mypy` return/optional typing issues in `session.py`, `search.py`, and `certificates.py`,
    - `detect-secrets` false positives from generated session-memory hashes and intentional synthetic password fixtures,
    - stale `cyclonedx-bom==4.1.5` pin in `scripts/generate_sbom.sh` that failed on Python 3.14 due to `lxml` wheel builds.
  - full gate suite passed:
    - `./scripts/certify.sh`
    - `./scripts/certify.sh --with-live-profile --profile tests/fixtures/firefox_profile`
    - `make dep-audit`
    - packaging dry-run + wheel install smoke
    - `make sbom`
    - `make sbom-verify`
  - short soak confidence pass passed with matrix lanes enabled:
    - run: `/var/tmp/foxclaw-soak/20260227T135950Z-ws66-premerge`
    - summary: `steps_total=16`, `steps_failed=0`, `overall_status=PASS`
    - ESR, beta, and nightly matrix scan stages all passed after bootstrap hardening.
  - archived evidence note: `docs/WS66_EVIDENCE_2026-02-27.md`.
  - merge recommendation:
    - Python is gate-clean and remains the canonical source of truth.
    - current worktree should not be merged as one unit until unrelated in-flight changes are separated into coherent review scopes.

### WS-67 - Change-Set Isolation and Merge-Scope Preparation

- Status: complete.
- Goal: separate the now-validated Python baseline into coherent reviewable scopes so merge decisions are based on bounded diffs instead of a mixed worktree.
- Scope:
  - classify the current dirty worktree into discrete review scopes (for example: threat-surface collectors, matrix hardening, docs/planning).
  - define the minimal mergeable Python baseline slice and identify what must stay out of that merge.
  - update docs/runbooks so merge sequencing reflects the isolated change-sets before any Rust branch work begins.
- Delivered:
  - classified the current dirty tree into three bounded merge scopes:
    - Scope A: threat-surface expansion and generator parity
    - Scope B: runtime/release hardening
    - Scope C: docs, evidence, and queue control
  - recorded exact file membership, validation floor, and merge order in `docs/WS67_SCOPE_PLAN_2026-02-27.md`.
  - advanced the queue so the next executable slices map directly to Scope A, Scope B, and Scope C instead of a generic merge-prep placeholder.

### WS-68 - Scope A Merge Pack

- Status: complete.
- Goal: land the WS-47..WS-54 threat-surface collector/rules/generator block as a bounded Python feature review scope.
- Delivered:
  - validated Scope A against the bounded file list defined in `docs/WS67_SCOPE_PLAN_2026-02-27.md`.
  - confirmed focused Scope A regressions pass:
    - `tests/test_adversary_profiles_script.py`
    - `tests/test_cookies.py`
    - `tests/test_hsts.py`
    - `tests/test_profile_artifacts.py`
    - `tests/test_rules_m3.py`
    - `tests/test_session.py`
    - `tests/test_snapshot_m5.py`
    - `tests/test_windows_auth_gen_scripts.py`
    - result: `63 passed, 7 skipped`
  - confirmed full baseline regression remains green:
    - `.venv/bin/pytest -q`
    - result: `265 passed, 7 skipped`
  - archived evidence note: `docs/WS68_EVIDENCE_2026-02-27.md`.

### WS-69 - Scope B Merge Pack

- Status: complete.
- Goal: land the matrix/runtime/release hardening changes required to keep the Python baseline operationally clean and release-rehearsable.
- Delivered:
  - validated Scope B against the bounded file list defined in `docs/WS67_SCOPE_PLAN_2026-02-27.md`.
  - confirmed Scope B operational hardening gates pass:
    - `./scripts/check_secrets.sh`
    - result: `[secrets] clean.`
    - `make sbom`
    - result: `[sbom] ok: path=sbom.cyclonedx.json spec=1.6 components=51 foxclaw_version=0.1.0`
    - `make sbom-verify`
    - result: `[sbom] ok: path=sbom.cyclonedx.json spec=1.6 components=51 foxclaw_version=0.1.0`
  - confirmed focused Scope B regressions pass:
    - `.venv/bin/pytest -q tests/test_container_matrix_bootstrap.py tests/test_sbom.py`
    - result: `7 passed`
  - confirmed full baseline regression remains green:
    - `.venv/bin/pytest -q`
    - result: `265 passed, 7 skipped`
  - archived evidence note: `docs/WS69_EVIDENCE_2026-02-27.md`.

### WS-70 - Scope C Merge Pack

- Status: complete.
- Goal: land the docs/evidence/queue-control updates after the bounded Python scopes are isolated and ready for merge.
- Delivered:
  - reconciled queue-control docs so the bounded Python scope sequence is explicitly closed.
  - confirmed `docs/PREMERGE_READINESS.md` and `docs/ROADMAP.md` both keep Rust bootstrap blocked until the validated Python baseline is merged.
  - advanced `Current Direction` to `WS-71`, the merge-execution checkpoint for the already-validated Python scopes.
  - archived evidence note: `docs/WS70_EVIDENCE_2026-02-27.md`.

### WS-71 - Python Merge Execution Checkpoint

- Status: complete.
- Goal: convert the validated Scope A/B/C work into coherent commit/merge units, rerun the bounded validations at those boundaries, and only then resume Rust branch work from the merged Python baseline.
- Delivered:
  - reran the Scope A validation floor and committed the feature block as `6ccf4b3` (`WS-68: land threat-surface expansion scope`).
  - reran the Scope B validation floor and committed the hardening block as `0d92517` (`WS-69: land runtime and release hardening scope`).
  - grouped the remaining docs/evidence/queue-control changes into a single closing docs commit for the Python baseline.
  - kept Rust bootstrap blocked and advanced the queue to `WS-72`, which covers the actual mainline merge and Rust branch handoff.
  - archived evidence note: `docs/WS71_EVIDENCE_2026-02-27.md`.

### WS-72 - Python Mainline Merge and Rust Branch Handoff

- Status: complete.
- Goal: merge the validated Python baseline to mainline, rerun merge-target gates there, and only then start `WS-31`/`WS-32` on a dedicated Rust branch.
- Delivered:
  - fast-forwarded the validated Python baseline onto a merge candidate rooted at `main`.
  - reran merge-target gates on that candidate:
    - `./scripts/certify.sh`
    - `./scripts/certify.sh --with-live-profile --profile tests/fixtures/firefox_profile`
    - `make dep-audit`
    - packaging dry-run + wheel install smoke
    - `make sbom`
    - `make sbom-verify`
    - `.venv/bin/pytest -q`
  - reserved the dedicated Rust handoff branch name `rust/ws31-bootstrap` for the next execution phase.
  - archived evidence note: `docs/WS72_EVIDENCE_2026-02-27.md`.

## Workslice Update Protocol

- On every slice completion:
  - set status to `complete`,
  - append shipped behavior under that slice,
  - link tests/docs changed,
  - record any follow-on slice split or reprioritization.
