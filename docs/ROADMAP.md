# Roadmap

This roadmap is FoxClaw's execution map for becoming a reference-grade browser security appliance, with Rust as the long-term runtime and deterministic contracts as the stability backbone.

Primary research inputs (online, current as of February 24, 2026):
- `docs/RESEARCH_2026-02-22_RUST_APPLIANCE.md`
- `docs/RESEARCH_2026-02-22_WINDOWS_SHARE_AUDIT.md`
- `docs/RESEARCH_2026-02-24_THREAT_SURFACE_EXPANSION.md`
- `docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md`

Archived reference (non-canonical draft; do not use as planning source of truth):
- `docs/archive/roadmap/ROADMAP_UPDATE_2026_DRAFT.md`

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
- Keep Python contracts, fixtures, and soak lanes stable enough to serve as the canonical merge baseline.
- Defer WS-31 `foxclaw-rs` workspace bootstrap and WS-32 contract canonicalization implementation until the Python baseline is revalidated, isolated into bounded merge units, and merged from mainline.
- Complete WS-46 enterprise Windows-share profile staging lane for deterministic local snapshot scanning.
- Expand fixture corpus for parser edge cases (SQLite damage modes, extension metadata anomalies, profile-version variance).

Exit criteria:

- Launch/fidelity gate is wired into synthesis workflows and enforced in CI where Firefox is available.
- Contract suite blocks incompatible output changes by default.
- Python mainline is explicitly treated as the canonical implementation and passes pre-merge hardening gates.
- The validated Scope A/B/C packs are merged cleanly before any Rust execution work starts.
- Windows-share runbook and staging harness are in place for enterprise remote-profile acquisition workflows.

### Phase 2.1: Audit Closeout Gate (Immediate)

Objectives:

- Keep WS-57 through WS-64 complete and move to WS-55B/WS-56 learning expansion.
- Restore all quality gates to green (`ruff`, `detect-secrets`, tests, typecheck, security gates).
- Correct command-level contract mismatches called out in `docs/AUDIT_2026-02-24.md`:
  - operational error exit code semantics,
  - UNC fail-closed parity for `scan` and `live`,
  - lock-marker consistency across scan/acquire/discovery paths.
- Align docs with runtime behavior before resuming feature expansion.
- Keep Rust execution work off mainline until this gate is green and the Python source-of-truth merge is complete.

Exit criteria:

- No open critical/high findings from `docs/AUDIT_2026-02-24.md`.
- `pytest -q tests/`, `ruff check .`, `mypy foxclaw`, `bandit`, `vulture`, and `detect-secrets` are all green.
- Documentation and CLI/runtime behavior are synchronized for exit codes, UNC policy, lock markers, and artifact names.
- A dedicated Rust branch can start from the validated Python baseline without unresolved mainline drift.

### Phase 2.5: Threat Surface Expansion (Q1 to Q2 2026)

Objectives:

- Complete WS-47 protocol handler hijack detection (`handlers.json` parsing, local executable flags).
- Complete WS-48 NSS certificate store audit (`cert9.db` rogue root CA detection).
- Complete WS-49 PKCS#11 module injection detection (`pkcs11.txt` validation).
- Complete WS-50 session restore data exposure (`sessionstore.jsonlz4` sensitive data detection).
- Complete WS-51 search engine integrity (`search.json.mozlz4` default engine validation).
- Complete WS-52 cookie security posture (`cookies.sqlite` session theft signals).
- Complete WS-53 HSTS state integrity (`SiteSecurityServiceState.txt` downgrade detection).
- Complete WS-54 CVE advisory simulation scenarios in Windows and Python profile generators.
- Complete WS-33 ATT&CK technique mapping for all finding classes.

Exit criteria:

- All new collectors have deterministic regression tests.
- New rules are present in both `balanced.yml` and `strict.yml`.
- Every new finding class maps to at least one ATT&CK technique.
- CVE simulation scenarios produce profiles that trigger the corresponding new rules.
- Soak harness covers new collectors without regression.

### Phase 2.6: Adaptive Scan Intelligence (Q2 2026)

Objectives:

- Keep WS-55A scan-history ingestion stable (append-only local SQLite; deterministic ordering).
- Complete WS-55B per-rule trend and novelty analysis from history snapshots.
- Complete WS-56 fleet-wide pattern correlation and prevalence enrichment.
- Add deterministic enrichment fields:
  - `trend_direction`
  - `novelty_score`
  - `fleet_prevalence`

Execution priority (next best step):

1. WS-55B trend/novelty summary surfaced in non-blocking outputs.
2. WS-56 fleet prevalence once WS-55B data quality is proven.
3. WS-47..WS-54 threat-surface collector/rule expansion in deterministic slices.

Exit criteria:

- Scan remains fully deterministic for identical inputs and identical history state.
- History database is local, append-only, and never consulted during rule evaluation.
- Enrichment fields (`trend_direction`, `novelty_score`, `fleet_prevalence`) are schema-validated.
- Soak harness validates self-learning enrichment without regression.

Phase 2.6 gating evidence baseline:

- Latest deep soak (`docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md`) completed
  with `120/120` passing steps and zero operational failures.
- Runtime bottleneck is clearly identified (`fuzz` ~88.7% of runtime), giving a
  concrete optimization target while preserving stable deterministic gates.

### Phase 3: Rust Core and Differential Execution (Q2 to Q3 2026)

Entry condition:

- Phase 2.1 has passed.
- WS-71 has executed and the Python source-of-truth baseline has been merged from mainline.

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

- ATT&CK technique mappings (accelerated from Phase 2.5) are ported to Rust with parity.
- Strengthen KEV/EPSS/CVSS signal normalization and explanation fields.
- Add OCSF-aligned export profile for downstream SIEM/XDR ingestion.
- Expand multi-profile fleet reporting with deterministic aggregation identity.
- Port self-learning enrichment layer to Rust.

Exit criteria:

- Threat-context fields are present, schema-validated, and deterministic.
- OCSF export mode is documented and covered by integration tests.
- Fleet outputs remain stable under versioned compatibility policy.
- Self-learning enrichment produces identical output in both Python and Rust engines.

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
