# Security Model

## Core Principles

- Offline-by-default: scan paths do not perform network calls.
- Read-only evidence collection: collectors never mutate host/profile state.
- Explicit phase separation: remediation is isolated from scan collection/evaluation.
- Deterministic outputs: stable sorting and schema contracts for machine consumers.

## Trust Boundary

### Evidence Boundary (`foxclaw/collect/*`, `foxclaw/profiles.py`)

- Inputs: local filesystem artifacts and SQLite files.
- Allowed actions: read-only open/stat/query operations.
- Disallowed actions: writing/modifying profile or system configuration.

### Evaluation Boundary (`foxclaw/rules/*`)

- Inputs: immutable evidence models + declarative rules.
- Output: finding objects only.
- Disallowed actions: host mutation, network activity.

### Reporting Boundary (`foxclaw/report/*`)

- Inputs: evidence/findings.
- Output: text/JSON/SARIF payloads.
- Disallowed actions: data collection and remediation side effects.

### Remediation Boundary (future phase)

- Kept isolated from collectors by design.
- Not shipped in the current CLI runtime surface.

## Operational Safety Assumptions

- Scan commands may run on live profiles; `--require-quiet-profile` can enforce additional guardrails.
- SQLite checks use read-only URI mode and integrity-oriented pragmas.
- Reports are outputs only and do not trigger host changes.

## CI and Upload Surface

- SARIF upload happens in GitHub Actions, not in FoxClaw runtime.
- Upload job requires `security-events: write` and is intentionally skipped for fork-origin pull requests.

## Exit Codes

The canonical exit-code contract is documented in `README.md`.
