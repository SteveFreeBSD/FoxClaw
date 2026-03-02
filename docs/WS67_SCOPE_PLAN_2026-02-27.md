# WS-67 Scope Plan (2026-03-02 refresh)

WS-67 goal: isolate the current mixed worktree into coherent review scopes before any merge or Rust branch work.

## Current State

Python runtime quality is no longer the blocker on this tree:

- `.venv/bin/pytest -q` -> `336 passed`
- `python scripts/docs_contract_check.py` -> `OK (86 markdown files checked)`
- mounted-share comprehensive soak -> `/var/tmp/foxclaw-soak/20260301T140921Z-comprehensive-precommit-ws82`
  - `cycles_completed=80`
  - `steps_total=1920`
  - `steps_failed=0`
  - `steps_interrupted=0`
  - `overall_status=PASS`

The remaining blocker is worktree shape: multiple completed slices are still mixed together and should not be committed as one blob.

Progress on 2026-03-02:

- Scope A is now committed as `5eb469b` (`WS-71: isolate Scope A runtime and generator hardening`).
- Scope B is now committed as `186469b` (`WS-71: isolate Scope B soak workflow hardening`).
- The remaining live worktree is now the Scope C docs/evidence block only.

## Commit Units

### Scope A: Runtime, Determinism, and Generator Hardening

Purpose:

- land the runtime correctness fixes, deterministic learning/history updates, docs-checker hardening, and Windows generator cleanup as one bounded Python behavior block.

Files:

- `foxclaw/acquire/windows_share.py`
- `foxclaw/cli.py` (`scan`/`live` share-parity, deprecated `--allow-unc-profile`, and `--learning-artifact-out` contract hunks only)
- `foxclaw/learning/history.py`
- `scripts/container_workspace_exec.sh`
- `scripts/docs_contract_check.py`
- `scripts/windows_auth_gen/README.md`
- `scripts/windows_auth_gen/generate_profiles.ps1`
- `scripts/windows_auth_gen/mutate_profile.mjs`
- `scripts/windows_auth_gen/package.json`
- `scripts/windows_auth_gen/package-lock.json`
- `scripts/windows_share_preflight.sh`
- `tests/test_cli_exit_codes.py` (share-parity and learning-artifact assertions only)
- `tests/test_container_matrix_bootstrap.py`
- `tests/test_docs_contract_check_script.py`
- `tests/test_profiles.py`
- `tests/test_scan_history.py`
- `tests/test_windows_auth_gen_scripts.py`
- `tests/test_windows_share_preflight_script.py`
- `tests/test_windows_share_source_detection.py`
- `tests/test_acquire_windows_share_cli.py` (snapshot-id collision avoidance assertion only)

Validation floor:

- `.venv/bin/pytest -q tests/test_docs_contract_check_script.py tests/test_cli_exit_codes.py tests/test_container_matrix_bootstrap.py tests/test_profiles.py tests/test_scan_history.py tests/test_windows_auth_gen_scripts.py tests/test_windows_share_preflight_script.py tests/test_windows_share_source_detection.py tests/test_acquire_windows_share_cli.py`
- `python scripts/docs_contract_check.py`
- `node --check scripts/windows_auth_gen/mutate_profile.mjs`
- `bash -n scripts/windows_share_preflight.sh scripts/container_workspace_exec.sh`

### Scope B: Soak Workflow and Mounted-Share Orchestration

Purpose:

- land WS-83 and WS-84 as one operational workflow block: corrected soak stop semantics, deterministic batch policy, and the first-class mounted-share comprehensive soak wrapper.

Files:

- `docs/CLI_CONTRACT.md`
- `docs/SOAK.md`
- `docs/WINDOWS_SHARE_STABILITY.md`
- `docs/WINDOWS_SHARE_TESTING.md`
- `foxclaw/acquire/windows_share_batch.py`
- `foxclaw/cli.py` (`windows-share-batch` include/exclude CLI hunks only)
- `scripts/soak_runner.sh`
- `scripts/soak_summary.py`
- `scripts/windows_share_comprehensive_soak.py`
- `tests/test_acquire_windows_share_batch.py`
- `tests/test_acquire_windows_share_cli.py` (batch include/exclude forwarding assertion only)
- `tests/test_soak_runner_script.py`
- `tests/test_soak_summary.py`
- `tests/test_windows_share_comprehensive_soak_script.py`

Validation floor:

- `.venv/bin/pytest -q tests/test_acquire_windows_share_batch.py tests/test_acquire_windows_share_cli.py tests/test_soak_runner_script.py tests/test_soak_summary.py tests/test_windows_share_comprehensive_soak_script.py`
- `python scripts/docs_contract_check.py`
- `bash -n scripts/soak_runner.sh`

### Scope C: Evidence, Queue, and Merge-State Reconciliation

Purpose:

- land only the remaining metadata, evidence, and planning updates that describe the validated Python baseline and the bounded merge order.

Files:

- `.gitignore`
- `CHANGELOG.md`
- `docs/INDEX.md`
- `docs/PREMERGE_READINESS.md`
- `docs/WORKSLICES.md`
- `docs/WS66_EVIDENCE_2026-02-27.md`
- `docs/WS67_SCOPE_PLAN_2026-02-27.md`
- `docs/WS72_EVIDENCE_2026-02-27.md`
- `docs/WS73_EVIDENCE_2026-02-27.md`

Validation floor:

- `python scripts/docs_contract_check.py`
- `.venv/bin/pytest -q`

## Shared-File Split Notes

- `foxclaw/cli.py` spans Scope A and Scope B; split by hunk instead of collapsing the runtime fixes and the soak wrapper CLI surface into one oversized commit.
- `tests/test_acquire_windows_share_cli.py` spans Scope A and Scope B for the same reason; keep the snapshot-id regression with Scope A and the batch include/exclude forwarding assertion with Scope B.
- `docs/WORKSLICES.md` and `docs/WS66_EVIDENCE_2026-02-27.md` mention WS-83 and WS-84, but they belong in Scope C because they are evidence/queue records, not runtime implementation.

## Merge Order

1. Scope A
2. Scope B
3. Scope C
4. After the three scopes are isolated, rerun the full merge-target gate set on the assembled Python baseline before any commit, push, or Rust handoff.

Rationale:

- Scope A contains the real Python runtime/determinism/generator behavior changes that were uncovered by the comprehensive review and pre-soak hardening.
- Scope B contains the operator-facing soak workflow improvements that were validated by the post-WS-83 mounted-share comprehensive soak.
- Scope C should land last so the evidence packet and queue state describe the actual isolated merge sequence that was chosen.

## Explicit Non-Goals

- No Rust bootstrap or `foxclaw-rs` files belong in these scopes.
- No repo-wide CI/workflow rewrites belong in these scopes.
- No generated soak artifacts or evidence bundle directories belong in these scopes.
- No formatting-only sweep belongs in these scopes.
