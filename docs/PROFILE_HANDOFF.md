# Profile System Handoff

This is the canonical onboarding and status document for profile realism work.
Start here before editing profile generation, fidelity scoring, or soak phases.

## Read Order and Ownership

1. `docs/PROFILE_HANDOFF.md`
   - Current state, implementation memory, open work, and anti-loop guidance.
2. `docs/PROFILE_SYNTHESIS.md`
   - Generator architecture, profile topography, and runtime usage.
3. `docs/PROFILE_FIDELITY_SPEC.md`
   - Fidelity gate contract and scoring behavior.
4. `docs/PROFILE_REVIEW_CHECKLIST.md`
   - Final merge/CTO review checklist.

## Current State Snapshot (2026-02-21)

- Workslices `WS-17` through `WS-23` are marked complete in `docs/WORKSLICES.md`.
- Soak pipeline includes native `synth` and `fuzz` phases with fidelity gating.
- Last local verification run: `make verify` passed on `2026-02-21`.
- Profile generation defaults:
  - deterministic seeds (`synth=424242`, `fuzz=525252`)
  - offline-by-default extension behavior
  - fidelity minimums (`synth=70`, `fuzz=50`)
- Realism layers currently implemented:
  - NSS artifacts (`key4.db`, `cert9.db`, `pkcs11.txt`)
  - HSTS state (`SiteSecurityServiceState.txt`)
  - web storage footprints (`storage/default/`)
  - favicon store (`favicons.sqlite`)

## Memory of Completed Work

- Added deterministic synthetic profile generator and realistic fuzz mutation flows.
- Added scenario archetypes:
  - `consumer_default`
  - `privacy_hardened`
  - `enterprise_managed`
  - `developer_heavy`
  - `compromised`
- Added runtime fidelity gate with JSON output (`scripts/profile_fidelity_check.py`).
- Integrated fidelity-gated synth/fuzz into soak orchestration and Make targets.

## Status Board

- Completed:
  - deterministic synth/fuzz generation and scenario archetypes
  - runtime fidelity gating in soak pipeline
  - advanced realism layers (NSS, HSTS, storage, favicons)
- In progress:
  - none currently; keep docs aligned with runtime behavior as changes land
- Deferred:
  - optional Firefox launch/open/close sanity gate for deep runs
  - expanded cross-OS baseline templates when needed

## Anti-Loop Guardrails

- Before changing profile generation behavior:
  - update the owning spec doc first (`PROFILE_SYNTHESIS` or `PROFILE_FIDELITY_SPEC`).
  - keep `PROFILE_REVIEW_CHECKLIST` as the only merge sign-off checklist.
- Before changing roadmap status:
  - update `WORKSLICES` together.
- Record every profile-system regression in `docs/MISTAKES.md` immediately after fix.
- Do not lower fidelity thresholds to "make runs green" without explicit rationale and doc updates.

## Update Protocol for Future Agents

When profile behavior changes, update all relevant docs in one PR:

1. `docs/PROFILE_HANDOFF.md` (state snapshot and memory)
2. Owning behavior doc:
   - `docs/PROFILE_SYNTHESIS.md` for generator/runtime behavior
   - `docs/PROFILE_FIDELITY_SPEC.md` for gate/scoring behavior
3. `docs/WORKSLICES.md` (status/deferred changes)
4. `docs/MISTAKES.md` (new regression lessons)
5. `docs/PROFILE_REVIEW_CHECKLIST.md` (only if review criteria changed)

## Source-Backed Constraints

- `prefs.js` is Firefox-managed and overwritten; `user.js` is user-managed and read by Firefox.
- Modern profile metadata uses `profiles.ini`/`installs.ini`, per-install sections, and `General/Version=2` semantics.
- Real extension state includes `extensions.json` with schema fields and associated extension state files and XPI artifacts.
- Real profile artifacts extend beyond minimal files (`places.sqlite`, `cookies.sqlite`, `prefs.js`) and include additional stores used by Firefox features.
- Enterprise policy behavior should align with `policies.json` contract and `ExtensionSettings`/`Certificates` formats.

## Primary References

- Firefox libpref (`prefs.js`/`user.js` behavior):
  - https://firefox-source-docs.mozilla.org/modules/libpref/index.html
- Toolkit profile service and profile layout:
  - https://firefox-source-docs.mozilla.org/toolkit/profile/
  - https://firefox-source-docs.mozilla.org/toolkit/profile/changes.html
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/profile/nsToolkitProfileService.cpp
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/profile/nsProfileLock.cpp
- Firefox data stores and schemas:
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/components/places/nsPlacesTables.h
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/netwerk/cookie/CookiePersistentStorage.cpp
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/mozapps/extensions/internal/XPIDatabase.sys.mjs
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/mozapps/extensions/AddonManager.sys.mjs
- Firefox backup resource coverage (real profile artifact sets):
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/components/backup/resources/AddonsBackupResource.sys.mjs
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/components/backup/resources/PreferencesBackupResource.sys.mjs
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/components/backup/resources/PlacesBackupResource.sys.mjs
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/components/backup/resources/SiteSettingsBackupResource.sys.mjs
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/components/backup/resources/FormHistoryBackupResource.sys.mjs
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/components/backup/resources/SessionStoreBackupResource.sys.mjs
  - https://hg.mozilla.org/mozilla-central/raw-file/tip/browser/components/backup/resources/CredentialsAndSecurityBackupResource.sys.mjs
- Firefox enterprise policy templates:
  - https://mozilla.github.io/policy-templates/
- AMO APIs:
  - https://mozilla.github.io/addons-server/topics/api/addons.html
  - https://addons.mozilla.org/api/v5/addons/search/
  - https://addons.mozilla.org/api/v5/addons/addon/\{guid\}/
