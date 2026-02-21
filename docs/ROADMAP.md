# Roadmap

This roadmap advances FoxClaw from a deterministic scanner into a feature-rich security application while preserving core safety guarantees.

## Non-Negotiable Constraints

- Scan runtime stays offline-by-default.
- Collectors remain read-only.
- Outputs remain deterministic and schema-stable.
- Trust boundaries remain explicit and testable.

## Phase 1: Detection Depth and Analyst Workflow

Target: near-term.

- Complete snapshot/diff analyst loop:
  - baseline snapshot export is available via `scan --snapshot-out`.
  - deterministic snapshot diff is available via `snapshot diff`.
- Add local extension posture checks:
  - baseline extension inventory from profile metadata is available.
  - baseline permission-risk classification from extension manifests is available.
  - baseline unsigned extension detection is available.
  - baseline debug/dev install detection is available (temporary install flags and volatile external source paths).
  - extend detection depth (debug/dev install states, richer risk model, suppression-aware workflows).
- Add suppression lifecycle:
  - baseline suppression by rule id + scope is available.
  - owner, reason, and expiration timestamp are required.
  - extend toward approval workflows and stronger governance reporting.
- Add stronger SARIF fidelity:
  - preserve stable fingerprints across runs.
  - keep path normalization rules strict.

Exit criteria:

- snapshot/diff, extension posture, and suppression paths covered by tests.
- no runtime network dependency introduced.
- SARIF upload remains GitHub Code Scanning compatible.

## Phase 2: Vulnerability Intel Foundation and Supply-Chain Integrity

Target: after phase 1 stabilization.

- Add explicit intelligence sync path (network-enabled by command, not by scan):
  - baseline `intel sync` command is available for deterministic source snapshot ingestion.
  - baseline normalized source adapter/indexing is available for `foxclaw.mozilla.firefox_advisories.v1`.
  - extend source adapters to fetch/normalize Mozilla/NVD/CVE/KEV datasets.
  - baseline local intelligence snapshot store now includes schema/versioned source metadata indexing.
- Add Mozilla CVE correlation:
  - baseline local Firefox version correlation from `compatibility.ini` is available.
  - baseline findings include fixed-version and source provenance with pinned snapshot id.
  - extend with richer vendor/NVD merge logic and confidence scoring.
- Add extension intelligence correlation:
  - baseline installed extension IDs/versions are correlated with AMO metadata and blocklist signals from pinned snapshots.
  - extend with richer publisher/reputation signals and confidence scoring.
- Signed policy packs:
  - baseline manifest pinning and optional Ed25519 signature verification are available
    via `--ruleset-trust-manifest` and `--require-ruleset-signatures`.
  - baseline key rotation and signature-threshold policy are available in trust manifest schema `1.1.0`.
  - extend toward externally distributed ruleset bundles and managed key distribution.
- CI provenance:
  - baseline artifact attestations for release build outputs are available.
  - baseline provenance references are linked from release artifacts.
- Release hardening:
  - baseline trusted publishing for package distribution is available.
  - baseline CycloneDX SBOM generation and verification are available in release packaging.
  - baseline dependency review policy gate is enforced in CI pull requests.
  - baseline scheduled dependency vulnerability sweeps are available.

Exit criteria:

- scan remains offline-by-default while consuming local intelligence snapshots.
- correlated findings are reproducible from profile + snapshot id.
- policy pack loading fails closed on verification errors.
- release artifacts are accompanied by verifiable provenance.
- dependency policy gates are enforced on pull requests.

## Phase 3: Risk Prioritization and Platform Integrations

Target: medium-term.

- Offline intelligence cache ingestion (explicit update phase only):
  - baseline KEV/EPSS-aware risk-priority metadata is available in correlated findings.
  - enrich findings with KEV/EPSS-aware prioritization metadata.
- Optional comprehensive live workflow:
  - provide a wrapper command that runs sync + scan pinned to the new snapshot.
  - keep deterministic replay by recording snapshot id in outputs.
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

Execution tracking:

- Ordered implementation slices are tracked in `docs/WORKSLICES.md`.
- Periodic technical and ecosystem checkpoints are recorded in date-stamped docs under `docs/`.
- Expanded pre-merge gate and planning runbook: `docs/PREMERGE_READINESS.md`.
