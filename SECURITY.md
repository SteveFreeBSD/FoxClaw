# Security Policy

## Supported Versions

Security fixes are provided for:

- `main` branch
- latest tagged release

Older releases are out of support unless explicitly stated.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting in this repository's Security tab.
If private reporting is unavailable, contact the repository owner directly.

Please include:

- affected commit or release
- reproduction steps
- impact and exploitability assessment
- proposed mitigation (if available)

## Disclosure Process

- Initial acknowledgement target: 5 business days.
- Triage and severity assignment follow acknowledgement.
- Public disclosure is coordinated after fix availability or agreed mitigation window.

## Supply-Chain and Reproducibility Controls

- CI workflows use immutable GitHub Action SHAs.
- Python dependency installation is pinned and deterministic in CI workflow definitions.
- Additional supply-chain controls are documented in workflow and build scripts.
- Certify evidence artifacts are emitted by `./scripts/certify.sh --emit-evidence-bundle`.
