# Contract Compatibility Policy

This document defines WS-32 compatibility rules for FoxClaw migration contracts.

## Scope

The compatibility policy applies to:

- scan JSON output contract (`schema_version` in `EvidenceBundle` payloads)
- scan SARIF output contract (`version: 2.1.0`)

It governs both Python and Rust engines.

## Frozen Baseline (WS-32)

Effective date: February 22, 2026.

- JSON scan schema: `1.0.0`
- SARIF schema: `2.1.0`
- Canonical fixture root: `tests/fixtures/migration_contracts/`

These fixtures are the migration baseline both engines must satisfy under deterministic mode.

## Compatibility Rules

1. No breaking changes without a major contract bump.
2. Breaking changes include:
   - removing required fields,
   - changing field types,
   - changing finding/rule identity semantics,
   - changing severity semantics,
   - changing evidence semantics in ways that alter deterministic meaning.
3. Non-breaking additions are allowed only when they are additive and optional.
4. Contract-affecting changes must include:
   - fixture regeneration (`scripts/generate_migration_contract_fixtures.py --write`),
   - fixture verification (`scripts/generate_migration_contract_fixtures.py --check`),
   - explicit documentation updates in this file and `docs/WORKSLICES.md`.

## Enforcement

Local enforcement commands:

```bash
python scripts/generate_migration_contract_fixtures.py --check
python scripts/verify_migration_contract_engine.py --engine-cmd ".venv/bin/python -m foxclaw" --engine-label python
python scripts/verify_migration_contract_engine.py --engine-cmd "./foxclaw-rs/target/debug/foxclaw-rs-cli" --engine-label rust
```

CI enforcement:

- `integration-testbed` validates fixture drift via `generate_migration_contract_fixtures.py --check`.
- `rust-parity-testbed` validates both engines against canonical fixtures.

## Determinism Requirements

- Engine execution must use `--deterministic`.
- Fixture normalization replaces repository-absolute paths with `<REPO_ROOT>` to keep artifacts host-independent.
- Any divergence from deterministic output is treated as a contract failure until explicitly classified and approved.
