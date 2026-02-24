# Scan Learning Loop

This document defines how FoxClaw becomes smarter from prior scans without
breaking deterministic scan behavior.

## Constraints

- `foxclaw scan` remains offline-by-default and read-only.
- Rule evaluation must not depend on mutable network data.
- Learning data is local, append-only, and auditable.
- Enrichment must be deterministic for identical inputs and identical history.

## Current State

- Per-scan outputs are deterministic (`foxclaw.json`, `foxclaw.sarif`, snapshots).
- Soak outputs already capture repeatable trend inputs:
  - `results.tsv`
  - `fidelity-summary.json`
  - `adversary-summary.json`
- Manual review is possible but not yet automated into a first-class learning store.

## Target State (WS-55/WS-56)

1. Ingest scan summaries into append-only local history storage.
2. Compute deterministic trend and novelty metrics per rule ID.
3. Add optional enrichment fields in output contracts:
   - `trend_direction`
   - `novelty_score`
   - `fleet_prevalence`
4. Feed stable learning summaries into profile generator weighting decisions.

## Immediate Implementation Order

1. WS-55A:
   - history ingestion command + schema + retention policy.
   - deterministic per-run learning artifact.
2. WS-55B:
   - trend/novelty computation and regression tests.
3. WS-56:
   - fleet prevalence/correlation on top of WS-55 data.

## Non-Goals

- No online model training in scan runtime.
- No hidden adaptive behavior that changes finding pass/fail semantics.
