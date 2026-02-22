# Browser Security Appliance Research - 2026-02-22

This research snapshot translates current (as of **February 22, 2026**) ecosystem signals into concrete implementation guidance for FoxClaw's Rust transition.

## Scope

- Focus area: browser security auditing appliances and adjacent controls used in enterprise security programs.
- Objective: identify technologies, tactics, and execution patterns FoxClaw should adopt to exceed current baseline practice.
- Constraint alignment: keep scan runtime offline-by-default, deterministic, and read-only.

## Method

- Sources were limited to primary references: official standards, official vendor documentation, and maintainer-owned project docs/repos.
- Findings were converted into:
  - architectural implications for FoxClaw,
  - prioritized execution tactics,
  - measurable roadmap gates.

## 2026 Landscape: What Mature Browser-Security Programs Are Doing

### 1) Policy-Centric Browser Governance Is Table Stakes

- Firefox enterprise policy surface is formalized and versioned through Mozilla policy templates and `policies.json` guidance.
- Chrome and Edge provide large enterprise policy catalogs with explicit device/user scoping patterns.
- CIS benchmarks package these policy controls into compliance-ready hardening baselines.

Implication for FoxClaw:
- Policy checks cannot be static or one-time. FoxClaw needs continuous policy-surface parity tracking and deterministic ruleset updates tied to vendor policy catalogs.

### 2) Artifact-Level Browser Auditing Is Still a Differentiator

- Mozilla documents key Firefox profile artifacts (`places.sqlite`, `cookies.sqlite`, `extensions.json`, `logins.json`, etc.).
- NSS defines security DB artifacts (`cert9.db`, `key4.db`) and SQLite-backed behavior.
- Fleet and Velociraptor demonstrate demand for machine-queryable browser artifact telemetry at fleet scale.

Implication for FoxClaw:
- Deep profile artifact parsing and profile-integrity assertions remain high-value and differentiating.
- Rust migration must preserve byte-level and semantic parity for these artifact paths.

### 3) Threat-Informed Prioritization Is Expected

- CISA KEV and EPSS are mainstream prioritization inputs.
- CVSS v4.0 is now part of the decision model for vulnerability severity context.
- ATT&CK techniques related to browser extension abuse and browser credential access are explicit and operationally relevant.

Implication for FoxClaw:
- Findings should include threat-context metadata, not only rule hits:
  - exploit-known status (KEV),
  - likelihood signal (EPSS),
  - ATT&CK technique mapping where appropriate.

### 4) Security Appliance Trust Model Is Moving to Signed Everything

- SLSA and in-toto frame provenance and attestation expectations.
- Sigstore bundles and transparency-style verification are becoming normal controls.
- TUF remains the core anti-rollback/compromise pattern for secure update channels.

Implication for FoxClaw:
- Intel snapshots, ruleset bundles, and release artifacts should all be verifiable with explicit trust roots and rollback protections.

### 5) Contracted Data Interchange Is Becoming Mandatory

- SARIF 2.1.0 remains key for code-scanning workflows.
- JSON Schema Draft 2020-12 is the practical baseline for contract validation.
- OCSF and CSAF matter for integration-heavy environments.
- CycloneDX and OpenVEX continue to expand in supply-chain reporting workflows.

Implication for FoxClaw:
- Output contracts must be versioned, validated, and migration-safe across Python and Rust.
- Rust cutover should be gated by schema and fixture parity, not implementation preference.

### 6) Rust Security Tooling Is Mature Enough for Appliance Build Discipline

- Rust 1.85 stabilized Edition 2024.
- Cargo lockfile discipline and reproducible dependency graphs are well documented.
- RustSec + `cargo-audit`, `cargo-deny`, and `cargo-vet` cover major dependency governance needs.

Implication for FoxClaw:
- Rust transition should embed dependency and supply-chain guardrails from day one, not as post-migration hardening.

## Tactics and Techniques FoxClaw Should Adopt

### Tactic A: Deterministic Acquisition and Evaluation Pipeline

Techniques:
- Enforce read-only profile acquisition paths.
- Validate SQLite artifact integrity before and after launch/fidelity gates.
- Require stable parse ordering and stable serialization ordering in all outputs.

Why this matters:
- Determinism is the core trust property for forensic and compliance use.

### Tactic B: Threat-Context-Enriched Findings

Techniques:
- Join local findings against pinned KEV/EPSS/CVE snapshot tables.
- Map extension and credential-store findings to ATT&CK techniques where defensible.
- Preserve source provenance and snapshot ID on each correlated finding.

Why this matters:
- Risk-priority outputs become actionable for SOC and vulnerability teams.

### Tactic C: Schema-First, Engine-Agnostic Contracts

Techniques:
- Freeze JSON and SARIF schemas using JSON Schema Draft 2020-12.
- Use fixture-driven parity tests that compare Python vs Rust normalized outputs.
- Add compatibility policy (`major/minor/patch`) for contract evolution.

Why this matters:
- Enables safe dual-engine period and controlled cutover.

### Tactic D: Signed Intel and Rules Distribution

Techniques:
- Add TUF-style metadata chain for intel/ruleset updates.
- Support Sigstore/in-toto attestations for published bundles.
- Enforce fail-closed signature and freshness checks.

Why this matters:
- Prevents poisoned update channels and rollback attacks.

### Tactic E: Appliance-Grade Build and Release Hygiene

Techniques:
- Gate on SLSA/in-toto provenance generation and verification.
- Publish CycloneDX SBOM and OpenVEX status where applicable.
- Run Rust dependency policy checks (`cargo-audit`, `cargo-deny`, `cargo-vet`) in CI.

Why this matters:
- Establishes trust posture expected of modern security products.

## Where FoxClaw Can Set the 2026 Standard

1. Deterministic browser-audit parity harness across two engines (Python + Rust) with published drift metrics.
2. Native ATT&CK + KEV + EPSS enrichment on local/offline snapshots.
3. Signed intelligence and rules update channel with explicit rollback resistance.
4. Contract-first output guarantees (JSON/SARIF now, OCSF export path next).
5. Reproducible release posture with provenance, SBOM, and vulnerability-exploitability context.

## Recommended Execution Order (Roadmap Input)

1. Lock contracts and parity harness foundations before deep Rust parser migration.
2. Complete profile-launch realism and cross-OS corpus hardening.
3. Bootstrap Rust workspace with shared canonical fixtures and strict differential tests.
4. Port parsers and rule evaluator incrementally with feature flags and fail-safe fallback.
5. Promote signed distribution and fleet-oriented export controls before final cutover.

## Risks and Mitigations

- Risk: Rust migration introduces silent behavior drift.
  - Mitigation: dual-engine differential CI gates with blocking thresholds.
- Risk: update channel compromise (intel/rulesets).
  - Mitigation: TUF-style metadata + signature verification + freshness/rollback checks.
- Risk: schema churn breaks downstream integrations.
  - Mitigation: versioned schemas + compatibility tests + deprecation windows.
- Risk: performance gains reduce transparency/debuggability.
  - Mitigation: preserve explainability/evidence fields as non-negotiable contract elements.

## Source Index

### Browser governance and artifacts

- Mozilla policy templates: https://mozilla.github.io/policy-templates/
- Firefox policy deployment (`policies.json`): https://support.mozilla.org/en-US/kb/customizing-firefox-using-policiesjson
- Firefox profile artifact mapping: https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile
- NSS shared DB internals: https://nss-crypto.org/reference/security/nss/legacy/reference/nss_tools__colon__certutil/index.html
- SQLite integrity checks: https://www.sqlite.org/pragma.html#pragma_quick_check
- Chrome policy list: https://chromeenterprise.google/policies/
- Edge policy reference: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies
- CIS benchmark catalog: https://www.cisecurity.org/cis-benchmarks
- Fleet browser telemetry example (`firefox_prefs`): https://fleetdm.com/tables/firefox_prefs
- Velociraptor browser artifact (`Windows.KapeFiles.Targets/Browser`): https://docs.velociraptor.app/artifact_references/pages/windows.kapefiles.targets/

### Threat and vulnerability prioritization

- CISA KEV program: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD vulnerability API docs: https://nvd.nist.gov/developers/vulnerabilities
- CVSS v4.0 specification: https://www.first.org/cvss/v4-0/specification-document
- EPSS model/API docs: https://www.first.org/epss
- ATT&CK Browser Extensions (T1176): https://attack.mitre.org/techniques/T1176/
- ATT&CK Credentials from Web Browsers (T1555.003): https://attack.mitre.org/techniques/T1555/003/

### Contracts and security data standards

- SARIF 2.1.0 standard: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- JSON Schema Draft 2020-12: https://json-schema.org/draft/2020-12
- OCSF schema docs (v1.6.0): https://schema.ocsf.io/1.6.0/
- CSAF 2.0 standard: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
- CycloneDX specification overview: https://cyclonedx.org/specification/overview
- OpenVEX spec: https://github.com/openvex/spec

### Supply-chain and Rust implementation controls

- SLSA source track docs: https://slsa.dev/docs/source/
- in-toto docs: https://in-toto.io/docs/
- Sigstore bundle format docs: https://docs.sigstore.dev/about/bundle/
- TUF spec repository: https://github.com/theupdateframework/specification
- Rust 1.85 / Edition 2024 announcement: https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/
- Cargo book (`Cargo.lock` and dependency management): https://doc.rust-lang.org/cargo/
- RustSec advisory database: https://github.com/RustSec/advisory-db
- `cargo-audit`: https://github.com/rustsec/rustsec/tree/main/cargo-audit
- `cargo-deny`: https://github.com/EmbarkStudios/cargo-deny
- `cargo-vet`: https://github.com/mozilla/cargo-vet
