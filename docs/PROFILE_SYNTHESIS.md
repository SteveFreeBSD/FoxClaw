# Realistic Profile Generation Architecture

The synthetic profile generator (`scripts/synth_profiles.py`) and fuzz generator
(`scripts/fuzz_profiles.py`) move FoxClaw testing from unstructured garbage data
to deterministic, scenario-driven Firefox profile simulation.

## Proposed Architecture: The `foxclaw-synth` Engine
The engine uses structured profile scaffolding plus controlled mutations to
construct reproducible Firefox-like workspaces.

### 1. SQLite Schemas & Data Simulation
We embed FoxClaw-compatible Firefox schema subsets and deterministic sample data:
- `places.sqlite` (History & Bookmarks)
- `cookies.sqlite`
- `permissions.sqlite`
- `content-prefs.sqlite`
- `formhistory.sqlite`
- `favicons.sqlite`

### 2. Extension Catalog + Optional Live Fetching
Generation is offline-by-default. The engine prefers cached/catalog-backed XPI
artifacts and only performs live AMO fetches when explicitly enabled with
`--allow-network-fetch`.

It synthesizes `extensions.json` records and extension payload paths with
signed-state metadata for realistic scanner behavior.

### 3. Scenario Archetypes
The generator selects from weighted archetypes (or accepts a forced scenario):
- **consumer_default**: Standard user profile posture.
- **privacy_hardened**: Strong privacy prefs and privacy extension bundle.
- **enterprise_managed**: Policy-driven profile with strict controls.
- **developer_heavy**: Dev-tool and power-user extension posture.
- **compromised**: Intentionally risky artifacts and settings for adversarial testing.

### 4. Advanced Realism Implementation
To ensure testing fidelity remains unbroken for future iteration:
- **NSS Certificate & Key Databases (`cert9.db` / `key4.db`)**:
  generated via `certutil` when available, with a SQLite fallback schema for
  environments without NSS tooling.
- **HSTS State (`SiteSecurityServiceState.txt`)**:
  serialized in Firefox-compatible tab-delimited format and aligned to HTTPS
  origins from `places.sqlite`.
- **Local Storage & IndexedDB (`storage/default/`)**:
  seeded with representative web/extension storage footprints.
- **`favicons.sqlite`**:
  page/icon mappings generated from `places.sqlite` URLs.

## Operational Guarantees

- Deterministic generation with `--seed` and per-profile `metadata.json`.
- Reproducible mutation controls via:
  - `--mutation-budget`
  - `--max-mutation-severity`
- Runtime realism gate:
  - `scripts/profile_fidelity_check.py`
  - default thresholds: synth `70`, fuzz `50`
- Soak integration captures provenance and fidelity summaries per cycle.

## Quick Usage

```bash
scripts/synth_runner.sh \
  --count 20 \
  --mode bootstrap \
  --seed 424242 \
  --mutation-budget 1 \
  --fidelity-min-score 70

scripts/fuzz_runner.sh \
  --count 1000 \
  --mode chaos \
  --seed 525252 \
  --mutation-budget 3 \
  --fidelity-min-score 50
```

## Limits and Intent

- Generated profiles are synthetic approximations for test realism, not byte-for-byte Firefox clones.
- Mutations intentionally create partial corruption to validate parser robustness.
- Fidelity scores are a gate for soak signal quality, not a cryptographic measure of authenticity.

## Troubleshooting

- `database or disk is full` / `No space left on device`
  - clean stale `/tmp/foxclaw-*` and `/var/tmp/foxclaw-soak/*` artifacts, then rerun.
- Fidelity gate fails in fuzz stage
  - inspect `fidelity-summary.json`, especially `below_min_count` and common `issues`.
  - tune mutation budget/severity only if failure is expected by scenario goals.
- Extension fetch mismatch
  - confirm catalog snapshot path and cache state.
  - keep `--allow-network-fetch` disabled for deterministic local/offline review runs.
- Reproduction request from reviewer
  - rerun with the exact logged `seed`, `mode`, `scenario`, `mutation_budget`, and `catalog_version` from `metadata.json`.

## Review Sign-Off Checklist

- `make verify` is green.
- `make soak-smoke` and `make soak-smoke-fuzz1000` are green.
- synth and fuzz fidelity outputs report `below_min_count=0` at configured thresholds.
- runner summaries report `Failed (crashed): 0`.
- docs and runtime defaults match:
  - synth min score `70`
  - fuzz min score `50`
  - offline-by-default extension fetching

Use `docs/PROFILE_REVIEW_CHECKLIST.md` as the final merge review checklist.

### Emulated Topography
```text
profile_dir/
├── bookmarkbackups/
├── browser-extension-data/
├── crashes/
├── datareporting/
├── extensions/
├── gmp-gmpopenh264/1.8.1.1/
├── sessionstore-backups/
├── storage/
│   └── default/
│       └── moz-extension+++uuid/
├── SiteSecurityServiceState.txt
├── cert9.db
├── content-prefs.sqlite
├── cookies.sqlite
├── extension-preferences.json
├── extension-settings.json
├── extensions.json
├── favicons.sqlite
├── formhistory.sqlite
├── handlers.json
├── key4.db
├── logins.json
├── permissions.sqlite
├── pkcs11.txt
├── places.sqlite
├── policies.json
├── prefs.js
└── user.js
```
