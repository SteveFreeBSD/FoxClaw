## Summary

<!-- What changed and why -->

## Validation

- [ ] `.venv/bin/pytest -q` passed locally
- [ ] `python scripts/check_ci_supply_chain.py` passed locally
- [ ] `./scripts/certify.sh` passed locally
- [ ] `./scripts/certify.sh --emit-evidence-bundle` passed locally

## Evidence and Supply-Chain Checks

- [ ] Action refs remain pinned to immutable SHAs
- [ ] Python installs use `requirements-dev.lock` (or explicit allow marker with justification)
- [ ] Evidence bundle contract remains valid against `EVIDENCE_BUNDLE_SPEC.md`

## Documentation and Scope

- [ ] Canonical docs updated for behavior/policy changes
- [ ] README and docs index links remain valid
- [ ] No drive-by refactors outside PR scope
