# CTO Review Packet (2026-02-26)

## Executive Summary

### Health Snapshot
- Local gate baseline is clean as of 2026-02-26: `./scripts/certify.sh` passed end-to-end and `pytest -q` reports `199 passed`.
- Core scan architecture is structured and reviewable: collection, rule evaluation, suppressions, and reporting are separated in `run_scan()` (`foxclaw/scan.py:37-187`).
- Deterministic output contracts are explicit in JSON/SARIF/snapshot/diff renderers (`foxclaw/report/jsonout.py:10-13`, `foxclaw/report/sarif.py:25-40`, `foxclaw/report/snapshot.py:49-81`, `foxclaw/report/snapshot_diff.py:45-92`).
- Trust boundaries are present and fail closed in critical paths: ruleset trust verification (`foxclaw/rules/trust.py:81-162`), profile path safety (`foxclaw/collect/safe_paths.py:38-68`), and UNC/share staging controls (`foxclaw/cli.py:226-243`, `foxclaw/cli.py:536-542`, `foxclaw/acquire/windows_share.py:520-526`).

### Readiness Call
- **CTO review ready for current scope.**
- WS-64 closure evidence is now recorded (`docs/WORKSLICES.md:836-845`, `docs/WS64_EVIDENCE_2026-02-26.md`).
- Remaining risk is primarily long-horizon maintainability (shared CLI orchestration and mount-detection hardening), not runtime correctness.

## Architecture Map

### Major Modules and Responsibilities
- CLI contracts and command surfaces: `scan`, `live`, `acquire`, `fleet`, `snapshot`, `intel`, `suppression`, `bundle` (`foxclaw/cli.py:105-1365`).
- Scan engine orchestration and data assembly (`foxclaw/scan.py:37-187`).
- Collectors and safe path/read-only handling (`foxclaw/collect/safe_paths.py:22-81`, `foxclaw/collect/artifacts.py:16-40`).
- Ruleset loading/evaluation/suppression and trust verification (`foxclaw/scan.py:141-149`, `foxclaw/rules/trust.py:81-206`).
- Intelligence sync (explicit network path) and offline correlation (`foxclaw/intel/sync.py:34-87`, `foxclaw/intel/correlation.py:96-145`).
- Deterministic reporters for JSON/SARIF/snapshot/fleet (`foxclaw/report/jsonout.py:10-13`, `foxclaw/report/sarif.py:25-40`, `foxclaw/report/snapshot.py:49-81`, `foxclaw/report/fleet.py:68-81`).
- Append-only local learning/history store (`foxclaw/learning/history.py:24-63`, `foxclaw/learning/history.py:151-212`).

### Data Flow and Trust Boundaries
1. CLI resolves profile and validates command invariants (`foxclaw/cli.py:220-331`).
2. Share-hosted profiles are staged locally before scanning (`foxclaw/cli.py:226-243`, `foxclaw/acquire/windows_share.py:577-606`).
3. Optional ruleset trust verification runs before evaluation and fails closed (`foxclaw/cli.py:309-316`, `foxclaw/rules/trust.py:94-162`).
4. Collectors enforce profile-root containment and symlink rejection (`foxclaw/collect/safe_paths.py:46-68`).
5. Rules + suppressions produce findings; reporters serialize deterministic ordering (`foxclaw/scan.py:143-170`, `foxclaw/report/snapshot_diff.py:45-56`).
6. Optional history ingestion is append-only and now receives explicit ruleset metadata (`foxclaw/cli.py:410-421`, `foxclaw/learning/history.py:151-175`).

### Deterministic Contracts
- JSON keys sorted (`foxclaw/report/jsonout.py:10-13`).
- SARIF findings sorted by severity/rule/evidence and emitted with sorted keys (`foxclaw/report/sarif.py:37-40`, `foxclaw/report/sarif.py:25-29`).
- Snapshot findings and high-finding IDs sorted (`foxclaw/report/snapshot.py:49-57`).
- Snapshot diff added/removed/changed ordering is stable and duplicate finding IDs fail closed (`foxclaw/report/snapshot_diff.py:45-56`, `foxclaw/report/snapshot_diff.py:131-142`).

## Top Risks (Ranked)

1. **Security Boundary:** Windows-share detection uses an SMB filesystem allowlist; unrecognized mount types can slip classification (`foxclaw/acquire/windows_share.py:118-126`).
2. **Maintainability:** `scan` and `live` duplicate substantial orchestration logic, increasing drift risk on future contract edits (`foxclaw/cli.py:105-454`, `foxclaw/cli.py:457-661`).
3. **Determinism Expectations:** Default timestamps remain runtime-generated unless deterministic modes/inputs are pinned (`foxclaw/models.py:327`, `foxclaw/intel/store.py:76-79`, `foxclaw/learning/history.py:321-324`).
4. **Compatibility Debt:** dual HSTS filename support should be time-boxed and eventually retired (`foxclaw/collect/artifacts.py:16-21`).
5. **Governance Discipline:** roadmap draft is now archived and must stay non-canonical (`docs/archive/roadmap/ROADMAP_UPDATE_2026_DRAFT.md`, `docs/ROADMAP.md:5-13`).

## Findings

### Critical
- None found in active runtime paths reviewed.

### High
- None found after remediation of history metadata wiring, HSTS contract normalization, and documentation drift (`foxclaw/cli.py:415-421`, `foxclaw/collect/artifacts.py:16-21`, `README.md:225`, `docs/PREMERGE_READINESS.md:62-70`, `docs/QUALITY_GATES.md:22-34`, `docs/VULNERABILITY_INTEL.md:95-101`).

### Medium
1. **Share-source classification relies on static mount fs-type list**
- Evidence: UNC or `_SMB_FILESYSTEM_TYPES` match is the decision gate (`foxclaw/acquire/windows_share.py:118-126`).
- Fix approach: add layered detector/fallback policy and broaden coverage tests for mount variants.
- Verification:
  - `pytest -q tests/test_windows_share_source_detection.py tests/test_cli_exit_codes.py`

2. **Command-path orchestration duplication (`scan`/`live`)**
- Evidence: repeated profile resolution, quiet-profile checks, scan execution, and output handling across two blocks (`foxclaw/cli.py:220-454`, `foxclaw/cli.py:560-661`).
- Fix approach: extract internal shared executor with explicit strategy hooks (`scan` vs `live` sync).
- Verification:
  - `pytest -q tests/test_cli_exit_codes.py tests/test_live_orchestration.py tests/test_determinism.py`

3. **Roadmap governance must remain canonical**
- Evidence: historical draft is archived and explicitly non-canonical (`docs/archive/roadmap/ROADMAP_UPDATE_2026_DRAFT.md`, `docs/ROADMAP.md:5-13`, `docs/WORKSLICES.md:74-93`).
- Fix approach: keep archive-only status and reject roadmap decisions sourced from draft docs.
- Verification:
  - `rg -n "ROADMAP_UPDATE_2026|ROADMAP_UPDATE_2026_DRAFT|ROADMAP.md|WORKSLICES.md" README.md docs`

### Low
1. **Dual HSTS artifact compatibility should be temporary and explicit**
- Evidence: collector supports both `.txt` and `.bin` (`foxclaw/collect/artifacts.py:16-21`), generator/fidelity canonicalize `.txt` (`scripts/profile_generation_common.py:370-393`, `scripts/profile_fidelity_check.py:14-31`).
- Fix approach: keep dual-read compatibility for one release window, then remove `.bin` once no legacy captures require it.
- Verification:
  - `pytest -q tests/test_profile_artifacts.py tests/test_profile_generation_scripts.py tests/test_profile_fidelity_check_script.py`

2. **Default runtime timestamps can confuse strict byte-for-byte replay expectations**
- Evidence: timestamp defaults in evidence/intel/history artifacts (`foxclaw/models.py:327`, `foxclaw/intel/store.py:76-79`, `foxclaw/learning/history.py:321-324`).
- Fix approach: keep messaging precise: ordering deterministic by default; timestamp determinism requires explicit pinned mode/inputs.
- Verification:
  - `pytest -q tests/test_determinism.py tests/test_snapshot_m5.py`

## Contract Table

| Command | Exit Codes | Artifacts Emitted | Determinism Expectation | Evidence |
|---|---|---|---|---|
| `foxclaw scan` | `0` clean, `1` operational error, `2` HIGH findings | optional JSON/SARIF/snapshot + optional learning artifact | sorted JSON/SARIF/snapshot ordering; timestamps pinned only in deterministic mode | `foxclaw/cli.py:38-40`, `foxclaw/cli.py:438-449`, `foxclaw/cli.py:344-408`, `foxclaw/report/jsonout.py:10-13`, `foxclaw/report/sarif.py:25-40`, `foxclaw/report/snapshot.py:49-81` |
| `foxclaw live` | `0/1/2` mirrored from scan outcome | same report outputs as `scan` | sync is explicit step; scan is pinned to produced snapshot id | `foxclaw/cli.py:457-661`, `foxclaw/cli.py:544-560` |
| `foxclaw acquire windows-share-scan` | returns scan code (`0/2`) or `1` on operational errors | `foxclaw.json`, `foxclaw.sarif`, `foxclaw.snapshot.json`, `stage-manifest.json` | staged local copy; deterministic manifest structure and explicit command capture | `foxclaw/acquire/windows_share.py:536-568`, `foxclaw/acquire/windows_share.py:586-668` |
| `foxclaw acquire windows-share-batch` | `1` if any operational failure, else `2` if findings, else `0` | `windows-share-batch-summary.json` + per-profile outputs | summary sorted by profile for stable output | `foxclaw/acquire/windows_share_batch.py:308-334` |
| `foxclaw fleet aggregate` | `0/1/2` | fleet JSON payload | profiles and finding records sorted deterministically | `foxclaw/cli.py:931-1056`, `foxclaw/report/fleet.py:68-81` |
| `foxclaw snapshot diff` | `0` no drift, `2` drift, `1` operational | diff JSON/stdout summary | deterministic added/removed/changed ordering | `foxclaw/cli.py:1068-1105`, `foxclaw/report/snapshot_diff.py:45-92` |
| `foxclaw intel sync` | `0` success, `1` operational | intel snapshot manifest/store material | source specs sorted; JSON normalization deterministic by default | `foxclaw/cli.py:1107-1192`, `foxclaw/intel/sync.py:89-111`, `foxclaw/intel/sync.py:141-149` |
| `foxclaw suppression audit` | `2` when expired/duplicate IDs, else `0`; `1` on load errors | JSON/stdout governance report | stable JSON key ordering on `--json` output | `foxclaw/cli.py:1195-1279`, `foxclaw/cli.py:1252-1256` |
| `foxclaw bundle fetch/install/verify` | `0` success, `1` operational | fetched bundle or validated install | signature checks fail closed | `foxclaw/cli.py:1282-1363`, `foxclaw/rules/bundle.py:40-111` |

## Test Posture

### Covered Well
- Full local gate chain is codified and executable (`scripts/certify.sh:64-151`).
- Exit-code semantics are exercised across command surfaces (`tests/test_cli_exit_codes.py:1-313`, `tests/test_acquire_windows_share_cli.py:1-514`).
- Deterministic output behavior is covered (`tests/test_determinism.py:1-66`, `tests/test_snapshot_m5.py:1-79`, `tests/test_snapshot_diff_m6.py:1-125`, `tests/test_sarif_m4.py:1-171`).
- Learning-store metadata and Firefox version extraction now have direct regression coverage (`tests/test_scan_history.py:299-356`).

### Coverage Gaps
- No automated docs-contract consistency gate (docs can drift unless manually reviewed).
- Share-source mount classification tests should expand beyond current UNC/cifs/local cases (`foxclaw/acquire/windows_share.py:118-126`).
- WS-64 evidence exists, but long-horizon soak evidence (multi-hour) is not yet part of a recurring gate (`docs/WS64_EVIDENCE_2026-02-26.md`, `docs/SOAK.md:1-151`).

### Flakiness Risk Zones
- Time-based fields without deterministic override (`foxclaw/models.py:327`, `foxclaw/intel/store.py:76-79`, `foxclaw/learning/history.py:321-324`).
- Host identity entropy in fleet metadata (`foxclaw/report/fleet.py:104-136`).
- Environment-dependent mount detection (`foxclaw/acquire/windows_share.py:109-126`).
