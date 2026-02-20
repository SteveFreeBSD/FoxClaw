# GitHub Actions Workflow

Workflow file: `.github/workflows/foxclaw-security.yml`

## Jobs

1. `test`
- Python matrix: `3.12`, `3.13`, `3.14`
- Installs `-e '.[dev]'`
- Runs `pytest -q -m "not integration"`

2. `integration-testbed`
- Python `3.13`
- Regenerates fixture matrix (`scripts/generate_testbed_fixtures.py --write`) to apply expected permission modes
- Validates deterministic testbed fixture manifest (`scripts/generate_testbed_fixtures.py --check`)
- Fails when fixture artifacts are stale or untracked (`git diff --exit-code -- tests/fixtures/testbed` plus untracked-file check)
- Runs `pytest -q -m integration`

3. `scan-balanced`
- Runs fixture scan against `tests/fixtures/firefox_profile`
- Emits `foxclaw.json` and `foxclaw.sarif`
- Accepts scan exit code `2` as expected findings signal
- Uploads both artifacts

4. `upload-sarif`
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

## Optional Containerized Firefox Smoke Workflow

Workflow file: `.github/workflows/foxclaw-firefox-container.yml`

- Triggered by weekly schedule and `workflow_dispatch`.
- Builds `docker/testbed/Dockerfile` (Firefox ESR + Python runtime).
- Runs `scripts/container_workspace_exec.sh` to copy source into a writable temp workspace, then executes `scripts/firefox_container_scan.sh`.
- Uploads:
  - `foxclaw.json`
  - `foxclaw.sarif`
  - `foxclaw.snapshot.json`
  - `firefox-headless.log`

## Forward Workflow Hardening Backlog

Planned next-level CI additions (non-runtime changes):

- Dependency review gate for pull requests.
- Scheduled dependency vulnerability checks.
- Release provenance attestations for build outputs.
- Optional SBOM artifact generation during release packaging.

See `docs/ROADMAP.md` and `docs/RESEARCH.md` for the implementation sequence and source references.
