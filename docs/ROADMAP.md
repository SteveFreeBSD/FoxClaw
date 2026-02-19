# Roadmap

This roadmap advances FoxClaw from a deterministic scanner into a feature-rich security application while preserving core safety guarantees.

## Non-Negotiable Constraints

- Scan runtime stays offline-by-default.
- Collectors remain read-only.
- Outputs remain deterministic and schema-stable.
- Trust boundaries remain explicit and testable.

## Phase 1: Detection Depth and Analyst Workflow

Target: near-term.

- Add extension posture checks:
  - permission-risk classification from extension manifests.
  - unsigned/debug extension detection.
- Add deterministic snapshot/diff:
  - create baseline snapshot.
  - compare current scan to baseline with stable diff output.
- Add suppression lifecycle:
  - suppress by rule id + scope.
  - require owner, reason, and expiration timestamp.
- Add stronger SARIF fidelity:
  - preserve stable fingerprints across runs.
  - keep path normalization rules strict.

Exit criteria:

- snapshot/diff and suppression paths covered by tests.
- no runtime network dependency introduced.
- SARIF upload remains GitHub Code Scanning compatible.

## Phase 2: Policy Packs and Supply-Chain Integrity

Target: after phase 1 stabilization.

- Signed policy packs:
  - external ruleset bundles with signature verification and manifest pinning.
- CI provenance:
  - artifact attestations for build outputs.
  - provenance references linked from release artifacts.
- Release hardening:
  - trusted publishing for package distribution.
  - dependency review and vulnerability gates in CI.

Exit criteria:

- policy pack loading fails closed on verification errors.
- release artifacts are accompanied by verifiable provenance.
- dependency policy gates are enforced on pull requests.

## Phase 3: Risk Prioritization and Platform Integrations

Target: medium-term.

- Offline intelligence cache ingestion (explicit update phase only):
  - enrich findings with KEV/EPSS-aware prioritization metadata.
- Policy language expansion:
  - evaluate CEL/OPA-based advanced policy packs behind strict interfaces.
- Multi-profile and fleet workflow support:
  - normalized machine outputs for aggregation.
  - stable report contracts for downstream SIEM pipelines.

Exit criteria:

- enrichment logic remains deterministic for a fixed intelligence snapshot.
- no direct network lookups in scan command paths.
- policy-engine expansion does not weaken collector boundary.

## Delivery Discipline

- Every phase must ship with:
  - architecture/security doc updates.
  - tests for new behavior.
  - deterministic output assertions.
  - rollback-safe feature flags when introducing new surfaces.
