# Issue: History Store Drops Ruleset Metadata (`ruleset_name`/`ruleset_version`)

## Status
Resolved on 2026-02-26.

## Context
`ScanHistoryStore.ingest()` now accepts explicit `ruleset_name` / `ruleset_version`, and `scan` passes resolved ruleset metadata into history ingestion.

## Reproduction / Verification
- Review `foxclaw/learning/history.py` and `foxclaw/cli.py`.
- Run scan-history tests that assert normalized metadata persistence.

## Acceptance Criteria
- Ruleset metadata is passed through an explicit contract path.
- History ingestion persists non-null `ruleset_name` and `ruleset_version` for normal scans.
- Tests enforce this behavior.

## Impacted Files
- `foxclaw/learning/history.py`
- `foxclaw/models.py`
- `foxclaw/scan.py`
- `tests/test_scan_history.py`
