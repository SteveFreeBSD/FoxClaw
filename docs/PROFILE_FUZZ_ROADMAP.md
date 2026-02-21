# Profile Fuzzer Realism Roadmap

This roadmap defines a small, source-backed execution plan to make FoxClaw's synthetic and randomized profile generation more realistic for real-world testing.

## Objectives

- Generate profiles that match real Firefox profile shapes and behaviors.
- Keep generated failures reproducible (`--seed`) and debuggable.
- Improve crash-finding and rule-coverage depth without introducing scan-time network dependency.

## Source-Backed Constraints

- `prefs.js` is Firefox-managed and overwritten; `user.js` is user-managed and read by Firefox.
- Modern profile metadata uses `profiles.ini`/`installs.ini`, per-install sections, and `General/Version=2` semantics.
- Real extension state includes `extensions.json` with schema fields and associated extension state files and XPI artifacts.
- Real profile artifacts extend beyond minimal files (`places.sqlite`, `cookies.sqlite`, `prefs.js`) and include additional stores used by Firefox features.
- Enterprise policy behavior should align with `policies.json` contract and `ExtensionSettings`/`Certificates` formats.

## Ordered Workslices

| ID | Status | Depends On | Outcome |
| --- | --- | --- | --- |
| WS-17 | complete | WS-16 | Source-backed profile fidelity spec and realism validator. |
| WS-18 | complete | WS-17 | AMO-backed extension catalog pipeline with pinned snapshots. |
| WS-19 | complete | WS-17 | Bootstrap-first profile generator (seed from Firefox-created profile). |
| WS-20 | complete | WS-18, WS-19 | Real-world scenario library with weighted archetypes. |
| WS-21 | complete | WS-20 | Controlled mutation engine with reproducible corruption operators. |
| WS-22 | complete | WS-21 | Runtime fidelity gate and realism scoring. |
| WS-23 | complete | WS-22 | Soak/CI integration with fixed-seed smoke and rotating-seed deep runs. |

## Workslice Details

### WS-17 - Profile Fidelity Spec

- Goal: codify what "realistic" means for FoxClaw profiles.
- Deliverables:
  - `docs/PROFILE_FIDELITY_SPEC.md` with required/optional artifact matrix.
  - Cross-file invariants (extension metadata <-> XPI files, prefs precedence, sqlite integrity expectations).
  - `scripts/profile_fidelity_check.py` to validate generated profiles.
- Acceptance:
  - Fidelity checker passes on testbed fixtures and known-good generated profiles.
  - Checker emits deterministic machine-readable output.

### WS-18 - AMO Extension Catalog Snapshot

- Goal: use real extension IDs/metadata/files from AMO in generation.
- Deliverables:
  - `scripts/build_extension_catalog.py` using AMO v5 search/detail endpoints.
  - Snapshot file under fixtures/intel (pinned timestamp + schema version).
  - Catalog fields: `guid`, `slug`, `average_daily_users`, `promoted`, permissions, current file URL/hash.
- Acceptance:
  - Catalog build is reproducible for a pinned source snapshot.
  - Generator can operate fully offline from cached snapshot + cached XPIs.

### WS-19 - Bootstrap-First Generator Core

- Goal: create profiles by starting from Firefox-created baselines, then mutating.
- Deliverables:
  - New mode in `scripts/synth_profiles.py`: `--mode bootstrap`.
  - Baseline profile scaffold aligned to common Firefox profile artifact layout.
  - Artifact coverage expanded to realistic sets (addons, prefs/search/session/site-settings/credentials stores).
  - Realism layers for NSS (`key4.db`/`cert9.db`), HSTS (`SiteSecurityServiceState.txt`), web storage (`storage/default`), and `favicons.sqlite`.
- Acceptance:
  - Generated profiles are accepted by `profile_fidelity_check.py` at >= target realism score.
  - Existing soak and fuzz runners remain backward-compatible.

### WS-20 - Scenario Library

- Goal: represent real user populations instead of unstructured randomness.
- Deliverables:
  - Scenario definitions (weighted): `consumer_default`, `privacy_hardened`, `enterprise_managed`, `developer_heavy`, `compromised`.
  - Each scenario defines extension bundles, prefs posture, policy posture, and artifact presence rules.
  - Scenario metadata emitted per generated profile (`metadata.json`).
- Acceptance:
  - Scenario mix is deterministic for a fixed seed.
  - Coverage report shows balanced scenario distribution over large runs.

### WS-21 - Controlled Mutation Engine

- Goal: replace pure chaos with realistic failure modes.
- Deliverables:
  - `--seed` support for synth/fuzz generators.
  - Mutation operators: partial/truncated writes, sqlite page/header damage, WAL/SHM drift, lockfile variants, permission drifts, malformed JSON fragments.
  - Mutation budget controls (`--mutation-budget`, `--max-severity`).
- Acceptance:
  - Every failing profile is reproducible from logged seed + mutation list.
  - Crash triage artifacts include exact mutation provenance.

### WS-22 - Runtime Fidelity Gate

- Goal: prevent low-fidelity synthetic data from polluting soak signals.
- Deliverables:
  - Realism scoring with hard minimum threshold (`scripts/profile_fidelity_check.py`).
  - Fail-closed behavior before scan stage when profiles are below threshold.
  - JSON summaries per run for deterministic triage.
- Acceptance:
  - Soak synth phase fails closed when fidelity threshold is not met.
  - Gate adds bounded runtime overhead and is configurable for smoke vs deep runs.

### WS-23 - Seamless FoxClaw Integration

- Goal: integrate new generation pipeline into current soak lifecycle without destabilizing existing gates.
- Deliverables:
  - `scripts/synth_runner.sh` and `scripts/fuzz_runner.sh` support scenario/seed/fidelity flags.
  - `scripts/soak_runner.sh` captures scenario, seed, realism score, and catalog version in logs/results.
  - Make targets for quick vs deep profile realism runs.
  - Doc updates in `docs/SOAK.md`, `docs/WORKSLICES.md`, and `docs/QUALITY_GATES.md`.
- Acceptance:
  - `make soak-smoke` stays green with fidelity gate enabled at smoke thresholds.
  - Deep soak runs produce deterministic provenance for reproducing any crash/failure.

## Integration Notes

- Keep scan runtime offline-by-default: all network use belongs to explicit snapshot-building commands.
- Continue fail-closed behavior for malformed profile data and trust boundaries.
- Treat realism features as additive: preserve current runner CLI behavior until migration is complete.
- For final sign-off workflow, follow `docs/PROFILE_REVIEW_CHECKLIST.md`.

## Review Evidence Pack

For merge/CTO review, include:

- `make verify` output (all gates green).
- Soak summary from:
  - `make soak-smoke`
  - `make soak-smoke-fuzz1000`
- Fidelity summaries:
  - synth: `below_min_count=0` at min score `70`
  - fuzz: `below_min_count=0` at min score `50`
- Crash counters from runner summaries:
  - `Passed (no crashes): N`
  - `Failed (crashed): 0`

## Deferred Follow-Ups

- Firefox launch/open/close profile sanity check as an optional deep-run gate.
- Expanded platform-variant baseline templates if cross-OS path semantics become a test target.

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
  - https://addons.mozilla.org/api/v5/addons/addon/{guid}/
