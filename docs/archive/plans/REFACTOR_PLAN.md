# Refactor Plan (Minimal Behavior Drift)

Historical internal planning note retained for engineering context.
Do not use this file for current execution ordering; use `docs/WORKSLICES.md` and the canonical docs linked from `docs/INDEX.md`.

## Spaghetti Hotspots (Current)

1. **Duplicated scan orchestration in CLI (`scan` vs `live`)**
- Evidence: duplicated control flow across `foxclaw/cli.py:220-454` and `foxclaw/cli.py:560-661`.
- Risk: contract drift across exits, artifact writes, and safety checks.

2. **Acquisition command-building logic is repeated across three paths**
- Evidence: `_build_stage_scan_manifest_command` (`foxclaw/cli.py:1366-1457`), `_build_scan_command` (`foxclaw/acquire/windows_share.py:428-465`), and batch wrapper command assembly (`foxclaw/acquire/windows_share_batch.py:103-154`).
- Risk: subtle argv contract drift in staged scan lanes.

3. **Share-source detection is a static allowlist**
- Evidence: `is_windows_share_profile_source()` uses UNC check + fs-type allowlist (`foxclaw/acquire/windows_share.py:118-126`).
- Risk: false negatives on unlisted SMB mount variants.

4. **Path normalization behavior is split across reporters**
- Evidence: SARIF path normalization (`foxclaw/report/sarif.py:31-49`), snapshot normalization (`foxclaw/report/snapshot.py:84-95`), fleet path normalization (`foxclaw/report/fleet.py:154-155`).
- Risk: output contract divergence across report formats.

5. **Roadmap/doc contract ownership is fragmented**
- Evidence: command/contract semantics spread across README/gates/workflow docs and code (`README.md:214-254`, `docs/QUALITY_GATES.md:12-34`, `docs/GITHUB_ACTIONS.md:20-34`, `foxclaw/cli.py:105-1365`).
- Risk: recurrent docs drift after CLI changes.

6. **Temporary dual-name HSTS compatibility is now intentional but transitional**
- Evidence: collector supports `.txt` and legacy `.bin` (`foxclaw/collect/artifacts.py:16-21`), while generator/fidelity canonicalize `.txt` (`scripts/profile_generation_common.py:370-393`, `scripts/profile_fidelity_check.py:14-31`).
- Risk: indefinite compatibility branch if no retirement plan is set.

## Staged Refactor Plan

### Stage 0 (Already Landed): Contract Correctness Fixes
- a) Target modules and intent:
  - `foxclaw/cli.py`, `foxclaw/learning/history.py`, `foxclaw/collect/artifacts.py`, docs.
  - Explicit history metadata handoff and HSTS naming normalization.
- b) Behavior invariants:
  - scan exit semantics unchanged,
  - history store remains append-only/idempotent,
  - artifact collection remains read-only.
- c) Verification commands:
  - `pytest -q tests/test_scan_history.py tests/test_profile_artifacts.py`
  - `./scripts/certify.sh`
- d) Rollback plan:
  - revert Stage 0 commit set; restore previous ingestion/artifact logic.

### Stage 1: Unify `scan`/`live` Core Executor
- a) Target modules and intent:
  - `foxclaw/cli.py`
  - extract shared internal executor for profile checks, trust verification, scan run, artifact writes.
- b) Behavior invariants:
  - `scan`/`live` exit codes remain `0/1/2`.
  - `live` still executes sync first and pins snapshot ID into scan.
- c) Verification commands:
  - `pytest -q tests/test_cli_exit_codes.py tests/test_live_orchestration.py tests/test_determinism.py`
- d) Rollback plan:
  - keep Stage 1 in one commit and `git revert` it if output diffs or exit regressions appear.

### Stage 2: Centralize Share-Lane Scan Command Builders
- a) Target modules and intent:
  - `foxclaw/cli.py`, `foxclaw/acquire/windows_share.py`, `foxclaw/acquire/windows_share_batch.py`
  - move all argv construction to one shared helper.
- b) Behavior invariants:
  - staged manifest `scan.command` semantics unchanged.
  - acquire scan wrappers preserve current defaults and flags.
- c) Verification commands:
  - `pytest -q tests/test_acquire_windows_share_cli.py tests/test_acquire_windows_share_batch.py tests/test_windows_share_scan_script.py`
- d) Rollback plan:
  - isolate changes to one module addition + callsite swaps; revert cleanly.

### Stage 3: Reporter Path Normalization Utility
- a) Target modules and intent:
  - `foxclaw/report/sarif.py`, `foxclaw/report/snapshot.py`, `foxclaw/report/fleet.py`
  - consolidate path normalization into one utility with explicit root semantics.
- b) Behavior invariants:
  - output schema and ordering unchanged.
  - deterministic mode behavior unchanged.
- c) Verification commands:
  - `pytest -q tests/test_sarif_m4.py tests/test_snapshot_m5.py tests/test_snapshot_diff_m6.py tests/test_fleet_aggregation.py tests/test_determinism.py`
- d) Rollback plan:
  - keep wrappers during migration and revert utility adoption if output hash diffs appear.

### Stage 4: Harden Share Source Detection Abstraction
- a) Target modules and intent:
  - `foxclaw/acquire/windows_share.py` + detection tests.
  - replace pure allowlist check with layered detector and explicit uncertain-path policy.
- b) Behavior invariants:
  - confidently network-mounted sources must still stage locally.
  - local non-share paths must not be over-blocked.
- c) Verification commands:
  - `pytest -q tests/test_windows_share_source_detection.py tests/test_cli_exit_codes.py`
- d) Rollback plan:
  - retain old detector behind feature flag and revert default if regressions surface.

### Stage 5: Documentation Contract Consolidation
- a) Target modules and intent:
  - add `docs/CLI_CONTRACT.md`; reduce duplicated command contract text in README/runbooks.
- b) Behavior invariants:
  - no CLI behavior changes; docs only.
- c) Verification commands:
  - `rg -n "@.*command\(" foxclaw/cli.py`
  - `rg -n "CLI_CONTRACT|ROADMAP_UPDATE_2026" README.md docs`
- d) Rollback plan:
  - docs-only revert if canonicalization introduces navigation confusion.

### Stage 6: Retire Legacy `.bin` HSTS Compatibility (Time-boxed)
- a) Target modules and intent:
  - `foxclaw/collect/artifacts.py`, related tests/docs.
  - remove `.bin` compatibility once legacy fixture/capture dependency is zero.
- b) Behavior invariants:
  - canonical `.txt` contract preserved.
  - collector remains read-only and deterministic.
- c) Verification commands:
  - `pytest -q tests/test_profile_artifacts.py tests/test_profile_generation_scripts.py tests/test_profile_fidelity_check_script.py`
  - `rg -n "SiteSecurityServiceState\.(txt|bin)" foxclaw scripts docs tests`
- d) Rollback plan:
  - restore dual-name list in one commit if legacy captures still require `.bin`.
