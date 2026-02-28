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
- Vendor-neutral NDJSON SIEM export with `foxclaw.finding` and `foxclaw.scan.summary` event types.
- Native Elastic Common Schema NDJSON output for modern SIEM/XDR ingestion.
- Native Wazuh proof lane pinned to `wazuh/wazuh-manager:4.14.3`.
- Machine-readable soak summaries and local memory-recall forensics for post-run review.
- Stage-first handling for share-hosted profile sources.
- Structured outputs for terminal summaries, JSON, SARIF, and snapshots.
- Fail-closed CI checks for immutable action refs and lockfile usage.
- Deterministic certify evidence bundle generation for assurance artifacts.

## Outputs

- JSON scan output (`--json`, `--output`)
- ECS NDJSON output (`--ecs`, `--ecs-out`)
- Vendor-neutral NDJSON output (`--ndjson`, `--ndjson-out`)
- SARIF 2.1.0 output (`--sarif`, `--sarif-out`)
- Snapshot output (`--snapshot-out`)
- Evidence bundle output (`artifacts/evidence/<git-sha>/`)

Delivery and merge gates: [docs/DELIVERY_GATES.md](docs/DELIVERY_GATES.md), [docs/PREMERGE_READINESS.md](docs/PREMERGE_READINESS.md)

## Current Baseline

- Python `main` is the current source-of-truth baseline.
- WS-75 through WS-81 are complete on `main`, covering production hardening, SIEM proof, native ECS export, soak-gate reliability, memory-recall forensics, and matrix-lane soak execution hardening.
- The latest reduced production gate passed on February 28, 2026 with `siem_wazuh` plus Firefox ESR/Beta/Nightly matrix build, version, and scan stages.
- Rust bootstrap remains intentionally blocked until that Python evidence packet is explicitly accepted.

## Trust Boundaries and Safety Model

- Collection and scan evaluation are read-only.
- Scan execution is offline-first; source synchronization is explicit.
- Remediation and mutation are intentionally out of scope.

System model references:
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
- [docs/SYSTEM_MODEL.md](docs/SYSTEM_MODEL.md)

## Quality Gates

```bash
./scripts/certify.sh
./scripts/certify.sh --emit-evidence-bundle
```

## CI Supply-Chain Policy

- GitHub Actions use pinned 40-character commit SHAs.
- Python dependencies are installed deterministically through pinned CI workflow commands.
- Workflow policy is fail-closed for mutable refs and dependency drift.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
.venv/bin/pytest -q
./scripts/certify.sh --emit-evidence-bundle
foxclaw profiles list
foxclaw scan --profile tests/fixtures/firefox_profile --json
```

## Documentation Map

- Docs index: [docs/INDEX.md](docs/INDEX.md)
- CTO review packet: [CTO_REVIEW_PACKET.md](CTO_REVIEW_PACKET.md)
- Assurance summary: [FOXCLAW_ASSURANCE_SUMMARY.md](FOXCLAW_ASSURANCE_SUMMARY.md)
- Merge readiness: [docs/PREMERGE_READINESS.md](docs/PREMERGE_READINESS.md)
- Audit baseline: [docs/AUDIT_2026-02-24.md](docs/AUDIT_2026-02-24.md)

## Security and Disclosure

- Disclosure policy: [SECURITY.md](SECURITY.md)
- Contributor expectations: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Licensed under [MIT](LICENSE).

<p align="center">
  <img src="assets/brand/foxclaw-banner.png" width="100%" alt="FoxClaw Assurance Pipeline">
</p>
