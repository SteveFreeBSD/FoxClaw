# WS-67 Scope Plan (2026-02-27)

WS-67 goal: isolate the current mixed worktree into coherent review scopes before any merge or Rust branch work.

## Current State

Python gates are green:

- `./scripts/certify.sh`
- `./scripts/certify.sh --with-live-profile --profile tests/fixtures/firefox_profile`
- `make dep-audit`
- packaging dry-run + wheel install smoke
- `make sbom`
- `make sbom-verify`
- short soak: `/var/tmp/foxclaw-soak/20260227T135950Z-ws66-premerge`

The remaining blocker is the worktree shape: multiple change themes are mixed together.

## Merge Scopes

### Scope A: Threat-Surface Expansion and Generator Parity

Purpose:

- land the WS-47..WS-54 product functionality and its direct regression coverage as one bounded feature block.

Files:

- `foxclaw/collect/artifacts.py`
- `foxclaw/collect/certificates.py`
- `foxclaw/collect/cookies.py`
- `foxclaw/collect/handlers.py`
- `foxclaw/collect/hsts.py`
- `foxclaw/collect/pkcs11.py`
- `foxclaw/collect/search.py`
- `foxclaw/collect/session.py`
- `foxclaw/rules/dsl.py`
- `foxclaw/rulesets/balanced.yml`
- `foxclaw/rulesets/strict.yml`
- `scripts/adversary_profiles.py`
- `scripts/windows_auth_gen/generate_profiles.ps1`
- `scripts/windows_auth_gen/mutate_profile.mjs`
- `scripts/windows_auth_gen/test.test` (deletion of empty placeholder)
- `tests/test_adversary_profiles_script.py`
- `tests/test_cookies.py`
- `tests/test_hsts.py`
- `tests/test_profile_artifacts.py`
- `tests/test_rules_m3.py`
- `tests/test_session.py`
- `tests/test_snapshot_m5.py`
- `tests/test_windows_auth_gen_scripts.py`

Validation floor:

- `.venv/bin/pytest -q tests/test_adversary_profiles_script.py tests/test_cookies.py tests/test_hsts.py tests/test_profile_artifacts.py tests/test_rules_m3.py tests/test_session.py tests/test_windows_auth_gen_scripts.py`
- `.venv/bin/pytest -q`

### Scope B: Runtime and Release Hardening

Purpose:

- land the soak/runtime hardening needed to keep matrix scans, secrets checks, and SBOM generation stable on the Python baseline.

Files:

- `docker/testbed/Dockerfile`
- `scripts/check_secrets.sh`
- `scripts/container_workspace_exec.sh`
- `scripts/generate_sbom.sh`
- `tests/test_container_matrix_bootstrap.py`
- `tests/test_sbom.py`

Validation floor:

- `./scripts/check_secrets.sh`
- `make sbom`
- `make sbom-verify`
- `.venv/bin/pytest -q tests/test_container_matrix_bootstrap.py tests/test_sbom.py`

### Scope C: Docs, Evidence, and Queue Control

Purpose:

- land only the planning/evidence changes that document the validated Python baseline and the bounded merge order.

Files:

- `docs/PREMERGE_READINESS.md`
- `docs/ROADMAP.md`
- `docs/SESSION_MEMORY.jsonl`
- `docs/SESSION_MEMORY.md`
- `docs/WORKSLICES.md`
- `docs/WS66_EVIDENCE_2026-02-27.md`
- `docs/WS67_SCOPE_PLAN_2026-02-27.md`

Validation floor:

- `.venv/bin/pytest -q`

## Merge Order

1. Scope A
2. Scope B
3. Scope C

Rationale:

- Scope A contains the main Python product delta and should be reviewed as feature behavior, rules, generators, and tests together.
- Scope B contains operational hardening and release-tooling fixes discovered while proving Python merge readiness.
- Scope C should land last so docs and queue state describe the actual isolated merge path that was chosen.

## Explicit Non-Goals

- No Rust bootstrap work belongs in these scopes.
- No repo-wide workflow rewrite belongs in these scopes.
- No broad formatting sweep belongs in these scopes.
