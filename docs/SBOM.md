# SBOM Runbook

This runbook defines local and CI expectations for CycloneDX SBOM generation and validation.

## Artifact Contract

- file name: `sbom.cyclonedx.json`
- format: CycloneDX JSON
- must include `foxclaw` component metadata with version

## Local Commands

Generate and verify SBOM:

```bash
make sbom
```

Verify existing SBOM artifact:

```bash
make sbom-verify
```

Direct script usage:

```bash
scripts/generate_sbom.sh --python .venv/bin/python --dist-dir dist --output sbom.cyclonedx.json
.venv/bin/python scripts/verify_sbom.py sbom.cyclonedx.json
```

## Release Workflow Behavior

Workflow: `.github/workflows/foxclaw-release.yml`

- build wheel + sdist.
- generate `sbom.cyclonedx.json` from wheel artifacts.
- verify SBOM contract before provenance/attestation steps.
- publish SBOM as release bundle and GitHub release asset.
- include SBOM in build-provenance attestation subject paths.

## Failure Policy

- If SBOM generation or validation fails, release publishing must stop.
- Do not reuse partially generated artifact sets; regenerate after fixing root cause.
