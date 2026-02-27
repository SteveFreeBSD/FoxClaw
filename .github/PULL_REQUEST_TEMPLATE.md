## Summary

<!-- What changed and why -->

## Validation

- [ ] `.venv/bin/pytest -q` passed locally
- [ ] `./scripts/certify.sh` passed locally
- [ ] `./scripts/certify.sh --emit-evidence-bundle` passed locally

## Evidence and Supply-Chain Checks

- [ ] Action refs remain pinned to immutable SHAs
- [ ] Python installs use pinned, deterministic dependency inputs
- [ ] Delivery and merge docs remain aligned (`docs/DELIVERY_GATES.md`, `docs/PREMERGE_READINESS.md`)

## Documentation and Scope

- [ ] Canonical docs updated for behavior/policy changes
- [ ] README and docs index links remain valid
- [ ] No drive-by refactors outside PR scope
