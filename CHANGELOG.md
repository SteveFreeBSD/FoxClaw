# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added
- Assurance summary front door: `FOXCLAW_ASSURANCE_SUMMARY.md`.
- Current Python production/SIEM evidence sequence:
  - `docs/WS75_EVIDENCE_2026-02-27.md`
  - `docs/WS76_EVIDENCE_2026-02-27.md`
  - `docs/WS77_EVIDENCE_2026-02-27.md`
  - `docs/WS78_EVIDENCE_2026-02-27.md`
  - `docs/WS79_EVIDENCE_2026-02-27.md`

### Changed
- README, docs index, and assurance docs now point at real current review artifacts instead of missing packet/spec placeholders.
- CTO review packet refreshed to the February 27, 2026 Python baseline with WS-75 through WS-79 commentary and review order.
- Pre-merge and workslice current-direction docs now explicitly include WS-79 forensic recall hardening.
- Pull request template now references current delivery/merge docs instead of a missing evidence bundle spec file.

## 2026-02-26 - Assurance Hardening and Evidence Rollout

### Changed
- Live share parity policy finalized with explicit staged acquisition guidance.
- CI/release supply-chain immutability policy enforced via pinned action refs and lockfile installs.
- Deterministic certify evidence bundle emission implemented and specified.

### References
- `DIFFS/patch-a-live-share-parity.diff`
- `DIFFS/patch-b-supply-chain-immutability.diff`
- `docs/PREMERGE_READINESS.md`
- `docs/DELIVERY_GATES.md`
