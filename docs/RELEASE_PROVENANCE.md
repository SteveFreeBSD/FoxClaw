# Release Provenance and Trusted Publishing

This runbook defines how FoxClaw release artifacts are built, attested, published, and verified.

Workflow file:

- `.github/workflows/foxclaw-release.yml`

## Release Controls

- Release trigger:
  - workflow runs on GitHub `release.published`.
- Version/tag gate:
  - workflow fails unless release tag matches `pyproject.toml` project version
    (accepts optional `v` prefix on tag names).
- Artifact build gate:
  - builds `sdist` + `wheel` with `python -m build`.
  - validates package metadata with `twine check`.
- SBOM gate:
  - generates CycloneDX JSON SBOM (`sbom.cyclonedx.json`) from built wheel artifacts.
  - validates SBOM structure and `foxclaw` component metadata.
- Provenance gate:
  - attests `dist/*`, `sbom.cyclonedx.json`, and `provenance.txt` with
    `actions/attest-build-provenance`.
- Trusted publishing gate:
  - publishes to PyPI using OIDC (`pypa/gh-action-pypi-publish`) with no API token.
  - requires configured PyPI trusted publisher and GitHub environment `pypi`.
- Release asset gate:
  - uploads `dist/*`, `sbom.cyclonedx.json`, and `provenance.txt` to the GitHub release.

## Dependency Policy Gates

Workflow file:

- `.github/workflows/foxclaw-security.yml`

Policy:

- Pull requests run `actions/dependency-review-action`.
- PR fails on `high`/`critical` dependency advisories.
- Gate executes as job `dependency-policy` and is required before `scan-balanced`.

## Verifying a Release

Prerequisites:

- GitHub CLI (`gh`) authenticated for repository read access.

Steps:

1. Download release artifacts from GitHub Releases:

```bash
gh release download <tag> --repo <owner>/<repo> \
  --pattern '*.whl' \
  --pattern '*.tar.gz' \
  --pattern 'sbom.cyclonedx.json' \
  --pattern 'provenance.txt'
```

2. Verify artifact attestations against the repository:

```bash
gh attestation verify *.whl --repo <owner>/<repo>
gh attestation verify *.tar.gz --repo <owner>/<repo>
gh attestation verify sbom.cyclonedx.json --repo <owner>/<repo>
gh attestation verify provenance.txt --repo <owner>/<repo>
```

3. Confirm package metadata and integrity locally:

```bash
python -m pip install --upgrade twine
python -m twine check *.whl *.tar.gz
sha256sum *.whl *.tar.gz sbom.cyclonedx.json provenance.txt
```

4. Validate SBOM contract:

```bash
python scripts/verify_sbom.py sbom.cyclonedx.json
```

5. Cross-check `provenance.txt`:
  - `release_tag` matches the expected release.
  - `commit` matches the source commit you audited.
  - `workflow_run` points to the passing release workflow run.

## Failure Policy

- If version/tag mismatch, attestation, or publish step fails:
  - do not re-use the same release artifact set.
  - fix root cause, cut a new tag, and rerun release.
