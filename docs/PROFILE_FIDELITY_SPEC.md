# Profile Fidelity Specification

This specification defines the minimum realism contract for synthetic and fuzzed Firefox profiles used by FoxClaw soak testing.

## Purpose

- Keep synthetic/fuzz profile data representative of real Firefox profile layouts.
- Ensure failures are meaningful for production parser/rules behavior.
- Provide a deterministic gate (`scripts/profile_fidelity_check.py`) before scan execution.

## Scope

- Applies to generated profiles from:
  - `scripts/synth_profiles.py`
  - `scripts/fuzz_profiles.py`
  - `scripts/synth_runner.sh`
  - `scripts/fuzz_runner.sh`
- This gate measures structural realism for soak signal quality.
- This gate does not claim cryptographic authenticity of generated artifacts.

## Required Artifacts

Each generated profile must include:

- `prefs.js`
- `places.sqlite`
- `cookies.sqlite`

Required checks:

- `places.sqlite` passes `PRAGMA quick_check`.
- `cookies.sqlite` passes `PRAGMA quick_check`.
- `prefs.js` and `user.js` (if present) only contain valid `user_pref(...)` lines (comments/blank lines allowed).

## Recommended Realism Artifacts

The following artifacts increase realism score and should be present for bootstrap profiles:

- `extensions.json`
- `extension-settings.json`
- `extension-preferences.json`
- `addonStartup.json.lz4`
- `browser-extension-data/`
- `key4.db`
- `cert9.db`
- `pkcs11.txt`
- `SiteSecurityServiceState.txt`
- `search.json.mozlz4`
- `xulstore.json`
- `handlers.json`
- `containers.json`
- `sessionstore.jsonlz4`
- `sessionstore-backups/`
- `storage/default/`
- `favicons.sqlite`
- `permissions.sqlite`
- `content-prefs.sqlite`
- `formhistory.sqlite`
- `logins.json`
- `logins-backup.json`

## Cross-File Invariants

- If `extensions.json` exists, it must parse as a JSON object with an `addons` list.
- Each addon `path` in `extensions.json` must exist in the profile directory.
- `prefs.js` reflects runtime state; `user.js` is optional and read-only from Firefox perspective.
- HSTS hosts in `SiteSecurityServiceState.txt` should align with HTTPS origins observed in `places.sqlite`.
- `favicons.sqlite` page rows should map to URLs present in `places.sqlite`.

## Scoring Model

`profile_fidelity_check.py` uses a 0-100 score:

- Required artifact presence: 30 points
- SQLite integrity checks: 20 points
- Pref syntax validation: 15 points
- Extension metadata/payload consistency: 20 points
- Optional artifact coverage: 15 points

Default runtime thresholds:

- `synth_runner.sh`: `--fidelity-min-score 70`
- `fuzz_runner.sh`: `--fidelity-min-score 50`

## CLI Contract

Primary command:

```bash
python scripts/profile_fidelity_check.py <profile-or-root> \
  --pattern "<glob>" \
  --min-score <N> \
  --enforce-min-score \
  --json-out <path>
```

Expected behavior:

- Prints per-profile `PASS` or `WARN` lines.
- Exits `1` when `--enforce-min-score` is set and any profile is below `--min-score`.
- Writes JSON summary with profile-level issues and aggregate counters.

Summary fields:

- `min_score`
- `average_score`
- `below_min_count`
- `profiles[]` entries including:
  - `score`
  - `required_present`
  - `sqlite_ok`
  - `prefs_syntax_ok`
  - `extensions_consistent`
  - `optional_artifact_count`
  - `issues`

## Gate Behavior

- With `--enforce-min-score`, any profile below threshold fails the phase.
- JSON output includes per-profile issues and aggregate average score.
- Gating remains local/offline; no scan-time network dependency is introduced.

## Common Failure Signals

- `extensions.json parse error`
  - usually from intentional fuzz truncation/malformed JSON operators.
- `prefs.js:<line> invalid pref syntax`
  - usually from mutation operators appending broken `user_pref(...)`.
- `<db>.sqlite quick_check failed`
  - usually from `sqlite_header_corrupt` mutation.
- `addons[n] missing payload <path>`
  - usually from `drop_extension_payload` mutation.

## Reviewer Acceptance Checklist

- `below_min_count=0` for:
  - synth smoke configuration (`--min-score 70`)
  - fuzz smoke/heavy configuration (`--min-score 50`)
- No crash records in synth/fuzz runner summaries (`Failed (crashed): 0`).
- Soak summary reports:
  - `overall_status=PASS`
  - `steps_failed=0`
