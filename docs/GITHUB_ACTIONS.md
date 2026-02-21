# GitHub Actions Workflow

Workflow file: `.github/workflows/foxclaw-security.yml`

## Jobs

1. `dependency-policy`
- Runs dependency policy gate.
- On pull requests:
  - executes `actions/dependency-review-action@v4`
  - fails on high/critical dependency advisories.
- On non-PR events:
  - emits a no-op note so downstream needs graph remains stable.

2. `test`
- Python matrix: `3.12`, `3.13`, `3.14`
- Installs `-e '.[dev]'`
- Runs `pytest -q -m "not integration"`

3. `quality-gates`
- Python `3.13`
- Runs:
  - `ruff check .`
  - `mypy foxclaw`
  - `bandit -q -r foxclaw -x tests`
  - `vulture foxclaw tests --min-confidence 80`
  - `detect-secrets scan --exclude-files '^tests/fixtures/testbed/manifest\.json$' $(git ls-files)` with non-empty-results failure

4. `integration-testbed`
- Python `3.13`
- Regenerates fixture matrix (`scripts/generate_testbed_fixtures.py --write`) to apply expected permission modes
- Validates deterministic testbed fixture manifest (`scripts/generate_testbed_fixtures.py --check`)
- Fails when fixture artifacts are stale or untracked (`git diff --exit-code -- tests/fixtures/testbed` plus untracked-file check)
- Runs `pytest -q -m integration`

5. `scan-balanced`
- Runs fixture scan against `tests/fixtures/firefox_profile`
- Emits `foxclaw.json` and `foxclaw.sarif`
- Accepts scan exit code `2` as expected findings signal
- Uploads both artifacts
- Requires:
  - `dependency-policy`
  - `test`
  - `quality-gates`
  - `integration-testbed`

6. `upload-sarif`
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

## Release Provenance and Trusted Publishing Workflow

Workflow file: `.github/workflows/foxclaw-release.yml`

Trigger:

- `release` with type `published`.

Jobs:

1. `build-dist`
- checks out the published tag.
- verifies release tag matches `pyproject.toml` project version (optional leading `v` allowed).
- builds wheel + sdist via `python -m build`.
- validates package metadata via `twine check`.
- writes `provenance.txt` with release/workflow pointers.
- uploads `dist/*` + `provenance.txt` as release bundle artifact.

2. `attest-provenance`
- downloads release bundle.
- creates artifact attestations with `actions/attest-build-provenance@v3`.

3. `publish-pypi`
- downloads release bundle.
- publishes to PyPI using OIDC trusted publishing (`pypa/gh-action-pypi-publish@release/v1`).
- requires environment `pypi`.

4. `upload-release-assets`
- uploads `dist/*` + `provenance.txt` to the GitHub release.

Verification guidance:

- see `docs/RELEASE_PROVENANCE.md`.

## Forward Workflow Backlog

Planned next-level CI additions (non-runtime changes):

- Optional SBOM artifact generation during release packaging.

See `docs/ROADMAP.md` and `docs/RESEARCH.md` for the implementation sequence and source references.
