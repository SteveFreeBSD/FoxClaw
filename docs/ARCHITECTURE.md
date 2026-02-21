# Architecture

## Architecture Goals

- Deterministic outputs suitable for CI gating and diffing.
- Strict trust boundaries between collection, evaluation, and reporting.
- Offline-by-default scanning with no runtime network dependency.
- Incremental path to a richer security platform without breaking current guarantees.

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
2. Collect local evidence through read-only collectors.
3. Optionally correlate local Firefox version against pinned local intel snapshot (`--intel-store-dir` / `--intel-snapshot-id`).
4. Build typed `EvidenceBundle` contract.
5. Evaluate ruleset into finding set.
6. Render deterministic output payloads.
7. Optional fleet path merges multiple profile scans into normalized host/profile/finding contracts.

## Trust Boundary Implementation

- Collection boundary (`foxclaw/collect/*`, `foxclaw/profiles.py`).
  - Reads files, metadata, and SQLite in read-only mode.
  - Never writes profile or system state.
- Evaluation boundary (`foxclaw/rules/*`).
  - Consumes evidence, emits findings only.
  - No host mutation or network I/O.
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
- `policypacks/` (planned).
  - signed external rule bundles validated before load.
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
