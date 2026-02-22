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

5. `rust-parity-testbed`
- Python `3.13` plus Rust toolchain (`stable`)
- Runs:
  - `cargo check --manifest-path foxclaw-rs/Cargo.toml`
  - `cargo build --manifest-path foxclaw-rs/Cargo.toml -p foxclaw-rs-cli`
  - `python scripts/rust_parity_runner.py` against deterministic testbed fixtures
- Uploads parity summary/artifacts for drift triage

6. `scan-balanced`
- Runs fixture scan against `tests/fixtures/firefox_profile`
- Emits `foxclaw.json` and `foxclaw.sarif`
- Accepts scan exit code `2` as expected findings signal
- Uploads both artifacts
- Requires:
  - `dependency-policy`
  - `test`
  - `quality-gates`
  - `integration-testbed`
  - `rust-parity-testbed`

7. `upload-sarif`
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
- `rust-parity-artifacts/summary.json`
- `rust-parity-artifacts/*` (parity case artifacts and diffs when present)

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

## Scheduled Dependency Vulnerability Sweep

Workflow file: `.github/workflows/foxclaw-dependency-audit.yml`

Trigger:

- weekly schedule.
- `workflow_dispatch`.

Job:

1. `dependency-vulnerability-sweep`
- installs project dependencies plus `pip-audit`.
- runs `scripts/dependency_audit.sh` to generate `pip-audit.json`.
- uploads `pip-audit.json` as artifact.
- fails when vulnerabilities are detected.

Runbook:

- see `docs/DEPENDENCY_AUDIT.md`.

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
- generates CycloneDX SBOM (`sbom.cyclonedx.json`) from built wheel artifacts.
- verifies SBOM structure and `foxclaw` component metadata (`scripts/verify_sbom.py`).
- writes `provenance.txt` with release/workflow pointers.
- uploads `dist/*` + `sbom.cyclonedx.json` + `provenance.txt` as release bundle artifact.

2. `attest-provenance`
- downloads release bundle.
- creates artifact attestations with `actions/attest-build-provenance@v3` for:
  - `dist/*`
  - `sbom.cyclonedx.json`
  - `provenance.txt`

3. `publish-pypi`
- downloads release bundle.
- publishes to PyPI using OIDC trusted publishing (`pypa/gh-action-pypi-publish@release/v1`).
- requires environment `pypi`.

4. `upload-release-assets`
- uploads `dist/*` + `sbom.cyclonedx.json` + `provenance.txt` to the GitHub release.

Verification guidance:

- see `docs/RELEASE_PROVENANCE.md`.
