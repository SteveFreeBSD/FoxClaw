<p align="center">
  <img src="assets/brand/foxclaw-banner.png" width="100%" alt="FoxClaw Assurance Pipeline">
</p>
<p align="center">
  <img src="assets/brand/foxclaw-mascot.png" width="420" alt="FoxClaw Security Appliance">
</p>

# FoxClaw

[![FoxClaw Security](https://github.com/SteveFreeBSD/FoxClaw/actions/workflows/foxclaw-security.yml/badge.svg)](https://github.com/SteveFreeBSD/FoxClaw/actions/workflows/foxclaw-security.yml)
[![Release Provenance](https://github.com/SteveFreeBSD/FoxClaw/actions/workflows/foxclaw-release.yml/badge.svg)](https://github.com/SteveFreeBSD/FoxClaw/actions/workflows/foxclaw-release.yml)
[![Dependency Audit](https://github.com/SteveFreeBSD/FoxClaw/actions/workflows/foxclaw-dependency-audit.yml/badge.svg)](https://github.com/SteveFreeBSD/FoxClaw/actions/workflows/foxclaw-dependency-audit.yml)
[![Firefox Container Smoke](https://github.com/SteveFreeBSD/FoxClaw/actions/workflows/foxclaw-firefox-container.yml/badge.svg)](https://github.com/SteveFreeBSD/FoxClaw/actions/workflows/foxclaw-firefox-container.yml)

## Overview

FoxClaw is a deterministic security inspection tool for Firefox profile posture evaluation. It applies auditable rulesets and emits repeatable, evidence-grade outputs suitable for CI enforcement and security review. It is read-only by design and offline-first during scan execution.

## What Is FoxClaw

FoxClaw provides deterministic browser profile posture inspection for assurance-focused engineering teams. It is built for reproducibility, traceability, and policy enforcement in CI and release workflows.

## Key Capabilities

- Deterministic Firefox profile discovery and selection.
- Read-only collection of preferences, filesystem permissions, policy artifacts, and extension posture.
- Declarative ruleset evaluation with trust-manifest verification support.
- Offline intelligence correlation with pinned snapshot identifiers.
- Stage-first handling for share-hosted profile sources.
- Structured outputs for terminal summaries, JSON, SARIF, and snapshots.
- Fail-closed CI checks for immutable action refs and lockfile usage.
- Deterministic certify evidence bundle generation for assurance artifacts.

## Outputs

- JSON scan output (`--json`, `--output`)
- SARIF 2.1.0 output (`--sarif`, `--sarif-out`)
- Snapshot output (`--snapshot-out`)
- Evidence bundle output (`artifacts/evidence/<git-sha>/`)

Evidence contract: [EVIDENCE_BUNDLE_SPEC.md](EVIDENCE_BUNDLE_SPEC.md)

## Trust Boundaries and Safety Model

- Collection and scan evaluation are read-only.
- Scan execution is offline-first; source synchronization is explicit.
- Remediation and mutation are intentionally out of scope.

System model references:
- [SYSTEM_MODEL_FROM_CODE.md](SYSTEM_MODEL_FROM_CODE.md)
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)

## Quality Gates

```bash
./scripts/certify.sh
./scripts/certify.sh --emit-evidence-bundle
```

## CI Supply-Chain Policy

- GitHub Actions use pinned 40-character commit SHAs.
- Python dependency installation is lockfile-first via `requirements-dev.lock`.
- Policy drift is checked by `scripts/check_ci_supply_chain.py`.

Policy checker: [scripts/check_ci_supply_chain.py](scripts/check_ci_supply_chain.py)

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --requirement requirements-dev.lock
.venv/bin/pytest -q
python scripts/check_ci_supply_chain.py
./scripts/certify.sh --emit-evidence-bundle
foxclaw profiles list
foxclaw scan --profile tests/fixtures/firefox_profile --json
```

## Documentation Map

- Docs index: [docs/INDEX.md](docs/INDEX.md)
- Packet index: [CTO_PACKET_INDEX.md](CTO_PACKET_INDEX.md)
- Assurance summary: [FOXCLAW_ASSURANCE_SUMMARY.md](FOXCLAW_ASSURANCE_SUMMARY.md)
- Posture baseline: [POSTURE_2026_GAP_REPORT.md](POSTURE_2026_GAP_REPORT.md)

## Security and Disclosure

- Disclosure policy: [SECURITY.md](SECURITY.md)
- Contributor expectations: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Licensed under [MIT](LICENSE).
