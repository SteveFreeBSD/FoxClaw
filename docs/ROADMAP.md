# Roadmap

This roadmap is FoxClaw's execution map for becoming a reference-grade browser security appliance, with Rust as the long-term runtime and deterministic contracts as the stability backbone.

Primary research input (online, current as of February 22, 2026): `docs/RESEARCH_2026-02-22_RUST_APPLIANCE.md`.

## End-State Definition

FoxClaw is considered "appliance-grade" when all of the following are true:

- Single-binary Rust scanner is the default runtime.
- Scan path remains offline-by-default and read-only.
- JSON/SARIF contracts are versioned, validated, and backward-compatible by policy.
- Findings include deterministic provenance, risk-priority context, and defensible evidence.
- Update channels for intel/rules are verifiable and rollback-resistant.

## Non-Negotiable Constraints

- No network access in `scan` execution paths.
- Collectors and parsers are read-only against target profiles.
- Output must be deterministic for identical inputs and snapshot IDs.
- Trust boundaries must fail closed (rules, intel, and release artifacts).
- Declarative rules DSL remains the policy authoring model (no embedded runtime scripting engine).

## Program Gates (Must Pass Before Advancing)

### Gate A - Contract Lock

- JSON and SARIF schemas are frozen for the migration window.
- Contract test fixtures are stable and version-pinned.
- Dual-engine comparator exists (Python vs Rust normalized outputs).

### Gate B - Differential Parity

- Rust output parity is >= 99.9% on canonical fixtures and generated profile corpus.
- Any mismatch must be categorized (bug, intentional contract bump, or unsupported edge).
- Zero silent drift is allowed on severity, rule IDs, evidence, or provenance fields.

### Gate C - Security and Trust

- Intel/rules update chain is signed and freshness-checked.
- Release provenance and SBOM/VEX artifacts are published and verifiable.
- Dependency and advisory policy gates are enforced in CI.

### Gate D - Operational Readiness

- Crash-free rate is validated on large synthetic + real-profile corpus.
- Performance and memory SLOs are met for defined profile-size tiers.
- Rollback plan is documented and tested.

## Phase Plan

### Phase 1: Foundation Shipped (Completed Baseline)

Status: substantially complete.

- Deterministic scanning, snapshot/diff workflow, and suppression lifecycle.
- Intel sync and correlation foundations (Mozilla, CVE/NVD, KEV, EPSS paths).
- Ruleset trust boundary controls and supply-chain baseline controls.
- Fleet aggregation and stable machine-readable report surfaces.

Why this matters:
- These capabilities are the stable substrate for Rust migration and appliance hardening.

### Phase 2: Contract and Corpus Hardening (Now through Q2 2026)

Objectives:

- Finish WS-28 launch-gate realism and cross-OS profile baseline hardening.
- Complete WS-30 schema lockdown with explicit JSON/SARIF version policy.
- Complete WS-31 `foxclaw-rs` workspace bootstrap and parity harness scaffolding.
- Expand fixture corpus for parser edge cases (SQLite damage modes, extension metadata anomalies, profile-version variance).

Exit criteria:

- Launch/fidelity gate is wired into synthesis workflows and enforced in CI where Firefox is available.
- Contract suite blocks incompatible output changes by default.
- Rust workspace compiles in CI and runs contract-smoke tests against canonical fixtures.

### Phase 3: Rust Core and Differential Execution (Q2 to Q3 2026)

Objectives:

- Establish Rust crate boundaries:
  - `foxclaw-rs-model` (contracts),
  - `foxclaw-rs-collect` (artifact readers),
  - `foxclaw-rs-rules` (declarative evaluator),
  - `foxclaw-rs-report` (JSON/SARIF emitters),
  - `foxclaw-rs-cli` (entrypoint).
- Implement normalized Python-vs-Rust diff runner in CI.
- Port highest-risk parsers first (`prefs.js`, `extensions.json`, `places.sqlite`, `cookies.sqlite`, NSS metadata artifacts).

Exit criteria:

- Differential runner is mandatory on pull requests touching parser/rules/report code.
- Rust scanner can produce contract-valid JSON/SARIF for the canonical fixture suite.
- Mismatch dashboard is available and trending down release-over-release.

### Phase 4: Threat-Context and Integration Leadership (Q3 to Q4 2026)

Objectives:

- Add ATT&CK technique mapping coverage for browser-specific finding classes.
- Strengthen KEV/EPSS/CVSS signal normalization and explanation fields.
- Add OCSF-aligned export profile for downstream SIEM/XDR ingestion.
- Expand multi-profile fleet reporting with deterministic aggregation identity.

Exit criteria:

- Threat-context fields are present, schema-validated, and deterministic.
- OCSF export mode is documented and covered by integration tests.
- Fleet outputs remain stable under versioned compatibility policy.

### Phase 5: Signed Distribution and Cutover Readiness (Q4 2026)

Objectives:

- Add TUF-style metadata and rollback checks for intel/rules update channels.
- Publish release artifacts with provenance attestations, CycloneDX SBOM, and OpenVEX where applicable.
- Enforce Rust dependency governance (`cargo-audit`, `cargo-deny`, `cargo-vet`) in CI.
- Run dual-engine production shadow mode with defined promotion criteria.

Exit criteria:

- End-to-end trust chain is verifiable for releases and update payloads.
- Rust engine meets parity, reliability, and SLO thresholds in shadow operation.
- Cutover decision package is complete (go/no-go with rollback procedures).

### Phase 6: Rust Default and Python Sunset (Target: Q1 2027)

Objectives:

- Promote Rust engine to default scanner runtime.
- Keep Python engine as temporary compatibility fallback behind explicit flag.
- Remove fallback after defined stabilization window and no critical regressions.

Exit criteria:

- Rust is default in docs, CI, and release artifacts.
- Python compatibility path is retired according to deprecation policy.
- Post-cutover audit confirms contract continuity and trust guarantees.

## Delivery Discipline

- Every phase ships with:
  - architecture/security doc updates,
  - deterministic tests and contract assertions,
  - operational runbooks,
  - explicit rollback strategy.
- New behavior is tracked in `docs/WORKSLICES.md` with dependency ordering.
- Research assumptions are refreshed quarterly in date-stamped docs under `docs/`.
