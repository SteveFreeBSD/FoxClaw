## Summary

<!-- What changed and why -->

## Validation

- [ ] `.venv/bin/pytest -q` passed locally
- [ ] `./scripts/certify.sh` passed locally
- [ ] `./scripts/certify.sh --emit-evidence-bundle` passed locally

## Evidence and Supply-Chain Checks

- [ ] Action refs remain pinned to immutable SHAs
- [ ] Python installs use pinned, deterministic dependency inputs
- [ ] Evidence bundle contract remains valid against `EVIDENCE_BUNDLE_SPEC.md`

## Documentation and Scope

- [ ] Canonical docs updated for behavior/policy changes
- [ ] README and docs index links remain valid
- [ ] No drive-by refactors outside PR scope
