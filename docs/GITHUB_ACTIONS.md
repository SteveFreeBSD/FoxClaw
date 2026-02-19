# GitHub Actions Workflow

Workflow file: `.github/workflows/foxclaw-security.yml`

## Jobs

1. `test`
- Python matrix: `3.12`, `3.13`, `3.14`
- Installs `-e '.[dev]'`
- Runs `pytest -q`

2. `scan-balanced`
- Runs fixture scan against `tests/fixtures/firefox_profile`
- Emits `foxclaw.json` and `foxclaw.sarif`
- Accepts scan exit code `2` as expected findings signal
- Uploads both artifacts

3. `upload-sarif`
- Downloads SARIF artifact
- Uploads SARIF using `github/codeql-action/upload-sarif@v4`
- Uses job permissions including `security-events: write`

## Permission Model

Top-level workflow permissions stay minimal (`contents: read`).

The SARIF upload job explicitly requests:

- `actions: read`
- `contents: read`
- `security-events: write`

This is required for GitHub Code Scanning ingestion.

## Fork Pull Request Behavior

Fork-origin pull requests do not receive a token with `security-events: write`.
The workflow handles this safely by skipping the upload job when:

- event is `pull_request`, and
- `github.event.pull_request.head.repo.fork == true`

This prevents insecure permission escalation patterns while keeping tests and fixture scanning active.

## Produced Artifacts

- `foxclaw.json`
- `foxclaw.sarif`

Artifacts are retained via `actions/upload-artifact` for troubleshooting and local replay.
