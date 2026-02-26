# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added
- Brand kit assets for GitHub landing:
  - `assets/brand/foxclaw-banner.png`
  - `assets/brand/foxclaw-mascot.png`
- Assurance summary front door: `FOXCLAW_ASSURANCE_SUMMARY.md`.
- Repository governance templates and hygiene docs:
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - `CODE_OF_CONDUCT.md`
  - `.github/PULL_REQUEST_TEMPLATE.md`
  - `.github/ISSUE_TEMPLATE/bug_report.md`
  - `.github/ISSUE_TEMPLATE/feature_request.md`
  - `.github/CODEOWNERS`

### Changed
- README reshaped for enterprise GitHub landing with focused overview, gates, outputs, trust boundaries, and canonical links.
- Packet index ordering updated to start with assurance summary.
- Documentation index updated with packet surfacing links.

## 2026-02-26 - Assurance Hardening and Evidence Rollout

### Changed
- Live share parity policy finalized with explicit staged acquisition guidance.
- CI/release supply-chain immutability policy enforced via pinned action refs and lockfile installs.
- Deterministic certify evidence bundle emission implemented and specified.

### References
- `DIFFS/patch-a-live-share-parity.diff`
- `DIFFS/patch-b-supply-chain-immutability.diff`
- `PATCHSET_PLAN.md`
- `EVIDENCE_BUNDLE_SPEC.md`
