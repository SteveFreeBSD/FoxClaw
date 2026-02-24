# Architecture

## Architecture Goals

- Deterministic outputs suitable for CI gating and diffing.
- Strict trust boundaries between collection, evaluation, and reporting.
- Offline-by-default scanning with no runtime network dependency.
- Incremental path to a richer security platform without breaking current guarantees.

## Architecture Invariants

- Stage-local-then-scan is mandatory for share-hosted Firefox profiles.
- Direct UNC profile scanning is disabled by default and requires explicit override.
- Collectors must validate all profile-file reads via `resolve_safe_profile_path()` or
  `iter_safe_profile_files()`.
- Unsafe profile paths (symlink traversal or root escape) must fail closed and surface as
  scan operational errors.

## Active Profile and Exit Semantics

- Share-hosted profile scans fail closed by default when lock markers (for example `parent.lock`)
  are present in the source profile.
- `--allow-active-profile` explicitly allows staging and scanning to proceed (`scan` auto-stage or
  `acquire windows-share-scan`); the stage manifest must record `source_lock_markers` so
  downstream systems can identify active-profile scans.
- `foxclaw scan` exit code `2` means scan completed with one or more `HIGH` findings; this is not
  an operational error condition.
- `--treat-high-findings-as-success` is available on acquisition wrappers and converts exit code
  `2` to success for pipelines and CI orchestration.

## Runtime Modules (Current)

- `foxclaw/cli.py`.
  - CLI orchestration, flag validation, and exit-code contract.
  - single-profile (`scan`) and multi-profile (`fleet aggregate`) workflow entrypoints.
- `foxclaw/profiles.py`.
  - deterministic profile discovery and selection.
- `foxclaw/collect/`.
  - read-only evidence acquisition from local profile/system paths, including extension inventory posture.
  - extension evidence classifies source kind (`profile`, `system`, `builtin`, `external`, `unknown`) and manifest status (`parsed`, `unavailable`, `error`).
  - extension posture marks debug/dev install signals from temporary install metadata and volatile external source paths.
- `foxclaw/rules/`.
  - ruleset parsing and constrained DSL evaluation.
  - suppression policy parsing and deterministic finding suppression.
  - optional ruleset trust verification (manifest-pinned digests + Ed25519 signatures).
- `foxclaw/report/`.
  - pure renderers (`text`, `json`, `sarif`, `fleet`) with no collection logic.
- `foxclaw/models.py`.
  - pydantic schema contract for evidence, findings, and summaries.
- `foxclaw/intel/`.
  - explicit intelligence snapshot sync path (`intel sync`) with local checksumed source material storage.
  - normalized source indexing (`source_indexes`, `mozilla_advisories`, `nvd_cves`,
    `cve_list_records`, `kev_catalog`, `epss_scores`) for offline correlation.
- `foxclaw/rulesets/`.
  - versioned policy packs (balanced, strict).

## Data Flow (Current)

1. Select profile (`profiles list` scoring or explicit `--profile`).
2. For share-hosted profile paths, stage locally first and emit `stage-manifest.json` provenance.
3. Resolve ruleset and optionally verify trust policy (`--ruleset-trust-manifest`, `--require-ruleset-signatures`).
4. Collect local evidence through read-only collectors.
5. Optionally correlate local Firefox version against pinned local intel snapshot (`--intel-store-dir` / `--intel-snapshot-id`).
6. Build typed `EvidenceBundle` contract.
7. Evaluate ruleset into finding set.
8. Render deterministic output payloads.
9. Optional fleet path merges multiple profile scans into normalized host/profile/finding contracts.

## Trust Boundary Implementation

- Collection boundary (`foxclaw/collect/*`, `foxclaw/profiles.py`).
  - Reads files, metadata, and SQLite in read-only mode.
  - Never writes profile or system state.
- Evaluation boundary (`foxclaw/rules/*`).
  - Consumes evidence, emits findings only.
  - No host mutation or network I/O.
- Ruleset trust boundary (`foxclaw/rules/trust.py`).
  - Validates manifest schema, pinned digest, and optional signatures before scan evaluation.
  - Fails closed on manifest, digest, key, or signature mismatch.
- Reporting boundary (`foxclaw/report/*`).
  - Formats evidence/findings only.
  - No collection side effects.
- Remediation boundary.
  - Intentionally excluded from current runtime surface.

## Determinism Contract

- Stable finding ordering by severity and rule id.
- Stable rules and results ordering in SARIF.
- Stable SARIF fingerprints from normalized evidence material.
- Sorted JSON output keys.
- Stable fleet aggregation ordering (profile identities + flattened finding records).
- Stable relative artifact URIs when paths resolve under repo/profile roots.

## Planned Expansion Points

The next-level roadmap is designed as additive modules so current scan guarantees remain intact.

- `state/` (planned).
  - signed snapshot format and deterministic diff engine.
- `suppression/` (planned).
  - additional suppression workflows beyond current runtime file-based lifecycle.
- `policypacks/` (active expansion area).
  - baseline trust manifest pinning and optional Ed25519 signature checks are available.
  - extend toward external bundle distribution, key-rotation policy, and multi-signature thresholds.
- `intel/` (active expansion area).
  - explicit update command for offline-cached threat intelligence metadata.
  - baseline Mozilla advisory normalization and offline CVE correlation in scan.
  - extend with NVD/KEV enrichment and extension threat-intel datasets.
- `attest/` (planned, release pipeline).
  - build provenance, signed releases, and artifact verification metadata.

## Non-Goals for Current Runtime

- Automatic remediation in scan command paths.
- Network lookups during evidence collection/evaluation.
- Dynamic plugin execution from untrusted sources at runtime.
