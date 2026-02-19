# Architecture

## Design Goals

- Deterministic scan and report outputs.
- Strict trust boundaries (read-only collection, isolated remediation).
- Offline-by-default runtime behavior.

## Module Layout

- `foxclaw/cli.py`
  - Command surface and exit-code orchestration.
- `foxclaw/profiles.py`
  - Firefox profile discovery and deterministic selection.
- `foxclaw/collect/`
  - Read-only evidence collectors.
  - No mutation side effects.
- `foxclaw/rules/`
  - Ruleset loader and constrained DSL evaluator.
- `foxclaw/report/`
  - Pure output rendering (`text`, `json`, `sarif`).
- `foxclaw/models.py`
  - Pydantic evidence and finding models (shared schema contract).
- `foxclaw/rulesets/`
  - Versioned YAML rulesets.

## Scan Data Flow

1. Resolve/select profile (`discover_profiles` or `--profile` override).
2. Collect read-only evidence from profile + system policy paths.
3. Build `EvidenceBundle` (stable internal schema).
4. Evaluate ruleset into deterministic findings.
5. Emit report formats without mutating evidence.

## Trust Boundaries

- Collection boundary:
  - `foxclaw/collect/*` only reads filesystem/SQLite in read-only mode.
- Evaluation boundary:
  - rule DSL consumes evidence models; no host mutation.
- Reporting boundary:
  - renderers format outputs only; they do not collect or mutate state.
- Remediation boundary:
  - `plan`/`apply` command surfaces are separate from scan code paths.

## Determinism Controls

- Stable sort order for findings (severity then rule id).
- Stable JSON key ordering.
- Stable SARIF rule/result ordering and fingerprints.
- Relative SARIF artifact URIs when evidence paths are inside repo/profile roots.
