# Docs Reconciliation Plan (2026-02-26)

Historical internal planning note retained for audit history.
Do not use this file as a source of truth; use `docs/INDEX.md`, `docs/CLI_CONTRACT.md`, `docs/WORKSLICES.md`, and `docs/ROADMAP.md`.

## Objective
Make documentation auditable and deterministic: one canonical source per contract, no conflicting roadmap branches, and no stale runbook commands.

## Inventory (`docs/`) with Purpose Tags

- `docs/ARCHITECTURE.md` - `spec`, `contract`
- `docs/AUDIT_2026-02-24.md` - `audit`
- `docs/DEPENDENCY_AUDIT.md` - `runbook`
- `docs/DEVELOPMENT.md` - `runbook`
- `docs/FLEET_OUTPUT.md` - `contract`
- `docs/GITHUB_ACTIONS.md` - `runbook`, `contract`
- `docs/INDEX.md` - `runbook` (canonical docs navigation)
- `docs/MISTAKES.md` - `audit`
- `docs/PREMERGE_READINESS.md` - `runbook`, `roadmap`
- `docs/PROFILE_FIDELITY_SPEC.md` - `spec`, `contract`
- `docs/PROFILE_HANDOFF.md` - `runbook`
- `docs/PROFILE_REVIEW_CHECKLIST.md` - `runbook`
- `docs/PROFILE_SYNTHESIS.md` - `spec`
- `docs/QUALITY_GATES.md` - `runbook`, `contract`
- `docs/RELEASE_PROVENANCE.md` - `runbook`, `contract`
- `docs/RESEARCH.md` - `research` (index)
- `docs/RESEARCH_2026-02-20.md` - `research`
- `docs/RESEARCH_2026-02-22_RUST_APPLIANCE.md` - `research`
- `docs/RESEARCH_2026-02-22_WINDOWS_SHARE_AUDIT.md` - `research`
- `docs/RESEARCH_2026-02-24_ADVERSARY_TESTBED.md` - `research`
- `docs/RESEARCH_2026-02-24_THREAT_SURFACE_EXPANSION.md` - `research`
- `docs/REVIEW_2026-02-20.md` - `audit`
- `docs/ROADMAP.md` - `roadmap` (canonical strategy)
- `docs/CLI_CONTRACT.md` - `contract` (canonical CLI surface)
- `docs/archive/roadmap/ROADMAP_UPDATE_2026_DRAFT.md` - `roadmap` (archived draft, non-canonical)
- `docs/RULESET_TRUST.md` - `contract`, `spec`
- `docs/SARIF.md` - `contract`
- `docs/SBOM.md` - `runbook`, `contract`
- `docs/SCAN_LEARNING_LOOP.md` - `spec`, `roadmap`
- `docs/SECURITY_MODEL.md` - `spec`, `contract`
- `docs/SOAK.md` - `runbook`
- `docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md` - `audit`
- `docs/SUPPRESSIONS.md` - `contract`
- `docs/TESTBED.md` - `runbook`
- `docs/VULNERABILITY_INTEL.md` - `spec`, `roadmap`
- `docs/WINDOWS_SHARE_STABILITY.md` - `runbook`
- `docs/WINDOWS_SHARE_TESTING.md` - `runbook`
- `docs/WORKSLICES.md` - `roadmap` (canonical execution queue)
- `docs/WS24_LIVE_WORKFLOW_ARCHITECTURE.md` - `spec`

## Drift / Contradictions Status

### Closed In This Pass
1. Workslice range mismatch fixed (`README.md:225`, `docs/WORKSLICES.md:74-93`).
2. Premerge queue updated from stale WS-57..61 references to current queue (`docs/PREMERGE_READINESS.md:62-70`, `docs/WORKSLICES.md:86-93`).
3. detect-secrets command docs aligned with executable source (`docs/QUALITY_GATES.md:22-34`, `docs/GITHUB_ACTIONS.md:23-28`, `scripts/check_secrets.sh:12-16`, `.github/workflows/foxclaw-security.yml:93-97`).
4. `audit --live-intel` doc drift removed; `live` wrapper now documented (`docs/VULNERABILITY_INTEL.md:95-101`, `foxclaw/cli.py:457-531`).
5. HSTS artifact contract normalized to `.txt` canonical with `.bin` legacy compatibility (`foxclaw/collect/artifacts.py:16-21`, `docs/SECURITY_MODEL.md:78-79`, `docs/WORKSLICES.md:81`).
6. WS-60 learning metadata claim now matches code path (`foxclaw/cli.py:415-421`, `foxclaw/learning/history.py:151-175`, `tests/test_scan_history.py:299-356`).
7. Canonical CLI contract created and linked (`docs/CLI_CONTRACT.md`, `README.md:214-223`).
8. Draft roadmap archived and canonical roadmap references clarified (`docs/archive/roadmap/ROADMAP_UPDATE_2026_DRAFT.md`, `docs/ROADMAP.md:5-13`).
9. Canonical docs index added and linked (`docs/INDEX.md`, `README.md:214-220`).

### Remaining Drift / Ambiguity
- No blocking drift remains for CTO review readiness.
- Residual maintenance risk: docs may still drift over time without an automated docs-contract CI check.

## Proposed Documentation IA (Canonical)

- `docs/ROADMAP.md`: strategy and phase gates only.
- `docs/WORKSLICES.md`: ordered execution status and dependencies only.
- `docs/CLI_CONTRACT.md`: command list, flags, exit codes, output artifacts, determinism expectations.
- `docs/INDEX.md`: canonical navigation and source-of-truth rules.
- `docs/ARCHITECTURE.md` + `docs/SECURITY_MODEL.md`: runtime boundaries and trust model.
- `docs/QUALITY_GATES.md`: high-level gate policy; executable commands referenced from `scripts/` and `.github/workflows/`.
- `docs/RESEARCH.md`: index only; dated research docs remain append-only evidence.

## Concrete Edits List (Path-Exact)

### Completed
1. `README.md` (workslice range + premerge description alignment).
- Verification: `rg -n "WS-01 through WS-|current execution queue" README.md`

2. `docs/PREMERGE_READINESS.md` (queue rewritten to current post-WS64 order).
- Verification: `rg -n "Current Execution Queue|WS-55B|WS-56" docs/PREMERGE_READINESS.md`

3. `docs/QUALITY_GATES.md` and `docs/GITHUB_ACTIONS.md` (detect-secrets parity).
- Verification: `rg -n "check_secrets.sh|detect-secrets scan --exclude-files" docs/QUALITY_GATES.md docs/GITHUB_ACTIONS.md scripts/check_secrets.sh .github/workflows/foxclaw-security.yml`

4. `docs/VULNERABILITY_INTEL.md` (live wrapper command correction).
- Verification: `rg -n "foxclaw live --source|audit --live-intel" docs/VULNERABILITY_INTEL.md`

5. `docs/SECURITY_MODEL.md`, `docs/ROADMAP.md`, `docs/WORKSLICES.md` (HSTS naming normalization).
- Verification: `rg -n "SiteSecurityServiceState\.(txt|bin)" docs/SECURITY_MODEL.md docs/ROADMAP.md docs/WORKSLICES.md foxclaw/collect/artifacts.py`

### Completed (Pre-CTO Closeout)
1. Created canonical CLI contract doc.
- Added: `docs/CLI_CONTRACT.md`
- Verification: `rg -n "@.*command\(" foxclaw/cli.py`

2. Archived non-canonical roadmap draft.
- Moved legacy `ROADMAP_UPDATE_2026.md` content to `docs/archive/roadmap/ROADMAP_UPDATE_2026_DRAFT.md`
- Added pointer in `docs/ROADMAP.md`.
- Verification: `rg -n "ROADMAP_UPDATE_2026|ROADMAP_UPDATE_2026_DRAFT" README.md docs`

3. Added docs index and linked from README.
- Added: `docs/INDEX.md`
- Updated: `README.md` docs section with canonical entrypoint.
- Verification: `rg -n "docs/INDEX.md" README.md docs`

## Single Source of Truth Rules

1. `ROADMAP.md` is strategy-only. No detailed status queue in roadmap text.
2. `WORKSLICES.md` is the only execution-status source (states, ordering, dependencies).
3. `RESEARCH.md` is the only research index; dated research files are evidence snapshots.
4. `CLI_CONTRACT.md` owns command/exit/artifact semantics; other docs link to it.
5. Gate logic is executable-first: `scripts/certify.sh`, `scripts/check_secrets.sh`, and `.github/workflows/*`; docs must mirror these exact surfaces.
