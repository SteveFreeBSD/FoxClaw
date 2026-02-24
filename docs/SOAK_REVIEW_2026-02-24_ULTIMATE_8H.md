# Soak Review: Ultimate 8h (2026-02-24)

Run directory: `/var/tmp/foxclaw-soak/20260224T035532Z-ultimate-8h`  
Branch/commit at run start: `main` @ `3b6eabb5fa48a7e0bb727d93a53ae496b15dd9ff`

## Outcome

- overall_status: `PASS`
- cycles_completed: `5`
- steps_total: `120`
- steps_failed: `0`
- duration_seconds: `31082`
- stop_reason: `deadline`

## Stage Runtime Distribution

Measured from `results.tsv`:

- `fuzz`: `27581s` (~88.7% of total runtime)
- `synth`: `2208s` (~7.1%)
- `matrix_scan_*`: `1169s` (~3.8%)
- all remaining stages combined: `<1%`

Interpretation:

- Deep-soak runtime is dominated by fuzz generation/launch-gate workloads.
- Deterministic scan/runtime stages are stable and comparatively cheap.

## Stability Signals

- Snapshot determinism: all cycles had `unique_hashes=1` per cycle and same snapshot hash across cycles.
- Matrix scans (`esr`, `beta`, `nightly`) completed each cycle with no operational failures.
- Adversary lane completed all runs with findings (expected) and no operational failures.

## Signal-Quality Observations

From fuzz fidelity logs (`5000` profiles across cycles):

- `extensions.json parse error`: `3695` occurrences
- `prefs.js invalid pref syntax`: `3640` occurrences
- `places.sqlite quick_check failed`: `905` occurrences
- `cookies.sqlite quick_check failed`: `885` occurrences
- multiple extension payload-missing variants also present

Interpretation:

- Fuzz currently emphasizes parser-corruption and file-integrity breakage heavily.
- This is useful for robustness testing but can underweight realistic threat-behavior signals.

## Generator/Detection Coverage Signals

- Synth lane is very stable (`avg fidelity ~99.5`, `below_min_count=0`, launch-gate failures `0`).
- Fuzz lane remains above gate (`avg fidelity ~66.61`, `below_min_count=0`) but is clustered near corruption-style artifacts.
- Adversary scenarios produced stable HIGH-finding pressure:
  - compromised: avg HIGH `7.0`
  - developer_heavy: avg HIGH `5.4`
  - enterprise_managed: avg HIGH `5.0`
  - privacy_hardened: avg HIGH `4.4`

## Decisions for Next Round

1. Keep current soak gate settings (they are stable and deterministic).
2. Rebalance fuzz mutation mix toward behavior-rich artifacts, not only structural corruption.
3. Implement scan-history learning ingestion (append-only) as the next engineering slice.
4. Feed learning outputs back into profile generators through explicit scenario weighting updates.

## Immediate Next Step

Start WS-55 phase A:

- ingest scan outputs into local append-only history store,
- compute per-rule trend and novelty summaries,
- publish deterministic learning artifact for each soak run.
