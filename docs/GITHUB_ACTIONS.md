# GitHub Actions Security Workflow

FoxClaw uses `.github/workflows/foxclaw-security.yml` to provide visible security signal in pull requests and on `main`.

## Workflow Summary

Triggers:
- `pull_request`
- `push` to `main`
- `workflow_dispatch`

Concurrency:
- `cancel-in-progress: true`
- group key scoped by workflow and branch/ref to avoid redundant runs on the same branch.

## Jobs

1. `test`
- Matrix: Python `3.12`, `3.13`, `3.14`
- Installs dependencies via `pip install -e '.[dev]'`
- Runs `pytest -q`

2. `scan-balanced`
- Runs FoxClaw against `tests/fixtures/firefox_profile` using `--profile` (no profile discovery dependency).
- Command writes:
  - `foxclaw.json`
  - `foxclaw.sarif`
- Exit code handling:
  - `0`: clean scan
  - `2`: findings present (expected for security signal), job remains successful
  - any other exit code fails the job
- Uploads artifacts: `foxclaw.json`, `foxclaw.sarif`

3. `upload-sarif`
- Downloads the SARIF artifact from `scan-balanced`.
- Uploads SARIF to GitHub Code Scanning using official action:
  - `github/codeql-action/upload-sarif@v4`
- Job permissions include `security-events: write`.

## SARIF Upload Behavior

The uploaded SARIF appears in the repository's Code Scanning UI, enabling:
- PR-level visibility of findings
- trend/history in code scanning alerts
- rule/result-level drill-down from FoxClaw output

The workflow does not add any runtime network call inside FoxClaw itself; network usage is limited to GitHub Actions infrastructure and artifact/code-scanning APIs.
