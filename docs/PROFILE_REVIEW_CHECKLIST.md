# Profile System Review Checklist

Use this checklist before requesting CTO or final merge review for profile realism work.

## 1) Code + Gate Health

- [ ] `make verify` passes.
- [ ] `bash -n scripts/synth_runner.sh scripts/fuzz_runner.sh scripts/soak_runner.sh` passes.
- [ ] Focused profile tests pass:
  - [ ] `.venv/bin/pytest -q tests/test_profile_generation_scripts.py tests/test_profile_fidelity_check_script.py`

## 2) Soak Evidence

- [ ] `make soak-smoke` passes (`steps_failed=0`).
- [ ] `make soak-smoke-fuzz1000` passes (`steps_failed=0`).
- [ ] Latest soak summary files are attached to review notes:
  - [ ] `summary.txt`
  - [ ] `results.tsv`
  - [ ] `logs/cycle-1-fuzz.log`

## 3) Fidelity Quality

- [ ] synth fidelity gate (`min=70`) has `below_min_count=0`.
- [ ] fuzz fidelity gate (`min=50`) has `below_min_count=0`.
- [ ] fuzz runner summary reports `Failed (crashed): 0`.
- [ ] synth runner summary reports `Failed (crashed): 0`.

## 4) Realism Artifact Coverage

- [ ] NSS artifacts present (`key4.db`, `cert9.db`, `pkcs11.txt`).
- [ ] HSTS artifact present (`SiteSecurityServiceState.txt`) and aligned with HTTPS history hosts.
- [ ] Storage artifacts present (`storage/default/...`).
- [ ] `favicons.sqlite` generated and mapped to `places.sqlite` URLs.

## 5) Determinism + Provenance

- [ ] profile `metadata.json` includes seed, mode, scenario, mutation metadata, and catalog version.
- [ ] soak manifest captures synth/fuzz seeds and fidelity thresholds.
- [ ] runner outputs include average realism score.

## 6) Documentation Alignment

- [ ] `docs/PROFILE_SYNTHESIS.md` reflects implemented runtime behavior.
- [ ] `docs/PROFILE_FIDELITY_SPEC.md` matches current scoring and thresholds.
- [ ] `docs/PROFILE_FUZZ_ROADMAP.md` marks delivered vs deferred items accurately.
- [ ] `docs/DEVELOPMENT.md` and `docs/SOAK.md` commands match current Makefile/script defaults.
