# FoxClaw Assurance Summary (2026-02-28)

## Current Readiness

- Python is the current source-of-truth baseline; Rust execution remains intentionally blocked until this evidence packet is explicitly accepted.
- Local regression baseline on February 28, 2026:
  - `.venv/bin/pytest -q` passed on the validated Python baseline.
- Merge-readiness gates rerun clean on February 28, 2026:
  - `./scripts/certify.sh`
  - `./scripts/certify.sh --with-live-profile --profile tests/fixtures/firefox_profile`
  - `make dep-audit`
  - package build + `twine check`
  - clean-venv install smoke
  - `make sbom`
  - `make sbom-verify`
- WS-75 through WS-82 are complete in the current Python baseline, covering:
  - native Wazuh smoke validation
  - vendor-neutral NDJSON SIEM export (`foxclaw.finding`, `foxclaw.scan.summary`)
  - native Elastic Common Schema NDJSON export
  - Elastic Security ECS acceptance proof against a pinned local stack
  - bounded soak-gate reliability with `soak-summary.json`
  - resilient local memory recall indexing and query fallback for post-run forensics
  - matrix-lane soak execution hardening with a passing reduced post-fix gate
- Wazuh proof target remains pinned to `wazuh/wazuh-manager:4.14.3`.

## Review Entry Points

- CTO review packet: [CTO_REVIEW_PACKET.md](CTO_REVIEW_PACKET.md)
- Merge-readiness runbook: [docs/PREMERGE_READINESS.md](docs/PREMERGE_READINESS.md)
- Workslice queue and current direction: [docs/WORKSLICES.md](docs/WORKSLICES.md)
- Canonical CLI contract: [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md)
- Documentation map: [docs/INDEX.md](docs/INDEX.md)

## Current Evidence Packet

- [docs/WS75_EVIDENCE_2026-02-27.md](docs/WS75_EVIDENCE_2026-02-27.md)
- [docs/WS76_SIEM_READINESS.md](docs/WS76_SIEM_READINESS.md)
- [docs/WS76_EVIDENCE_2026-02-27.md](docs/WS76_EVIDENCE_2026-02-27.md)
- [docs/WS77_EVIDENCE_2026-02-27.md](docs/WS77_EVIDENCE_2026-02-27.md)
- [docs/WS78_EVIDENCE_2026-02-27.md](docs/WS78_EVIDENCE_2026-02-27.md)
- [docs/WS79_EVIDENCE_2026-02-27.md](docs/WS79_EVIDENCE_2026-02-27.md)
- [docs/WS80_EVIDENCE_2026-02-28.md](docs/WS80_EVIDENCE_2026-02-28.md)
- [docs/WS81_EVIDENCE_2026-02-28.md](docs/WS81_EVIDENCE_2026-02-28.md)
- [docs/WS82_EVIDENCE_2026-02-28.md](docs/WS82_EVIDENCE_2026-02-28.md)

## Recommended CTO Review Order

1. Reconfirm the Python-first hold and merge ordering in [docs/WORKSLICES.md](docs/WORKSLICES.md) and [docs/PREMERGE_READINESS.md](docs/PREMERGE_READINESS.md).
2. Review the production/SIEM/ECS implementation sequence in WS-75 through WS-82.
3. Use [CTO_REVIEW_PACKET.md](CTO_REVIEW_PACKET.md) for the condensed architecture, risks, and merge commentary.

## Remaining Risks

- `memory_query.py` falls back to `LIKE` matching when SQLite FTS5 support or `checkpoints_fts` is unavailable; that keeps operator recovery working but is slower and less expressive than FTS.
- Windows-share mount classification and CLI orchestration duplication remain medium-severity maintainability risks; they are not blockers for the current Python push/merge packet.
- The overnight pre-fix soak remains on disk as historical failure evidence; current review should treat WS-80 as the authoritative post-fix soak state.
- ECS output intentionally preserves FoxClaw-specific detail under a `foxclaw` extension namespace because ECS does not natively model Firefox profile identity or FoxClaw scan summary fields.
