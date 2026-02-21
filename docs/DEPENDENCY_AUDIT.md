# Dependency Vulnerability Audit

FoxClaw runs scheduled dependency vulnerability sweeps to catch newly disclosed issues in
Python dependencies between code changes.

## CI Workflow

Workflow file:

- `.github/workflows/foxclaw-dependency-audit.yml`

Behavior:

- runs weekly on schedule and on manual dispatch.
- installs project dependencies plus `pip-audit`.
- audits the active environment via `scripts/dependency_audit.sh`.
- uploads `pip-audit.json` as a workflow artifact.
- fails the job when vulnerabilities are detected.

## Local Run

Run the same check locally:

```bash
make dep-audit
```

This writes output to:

- `dependency-audit.json`

## Triage Workflow

When vulnerabilities are detected:

1. identify affected package(s) and advisory ids from `pip-audit.json`.
2. check if patched versions are available.
3. upgrade pinned dependency ranges and regenerate lock/install metadata as needed.
4. rerun `make dep-audit` and standard certification gates.
5. document unresolved exceptions with owner and remediation deadline.
