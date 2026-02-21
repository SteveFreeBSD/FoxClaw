# Development

## Environment Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e '.[dev]'
```

## Local Verification Commands

Run from repository root.

```bash
pytest -q -m "not integration"
python scripts/generate_testbed_fixtures.py --write
pytest -q -m integration
ruff check .
mypy foxclaw
python scripts/generate_testbed_fixtures.py --check
```

Generate fixture outputs and keep exit-code semantics intact (`2` means findings, not crash):

```bash
scan_exit=0
python -m foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --output foxclaw.json \
  --sarif-out foxclaw.sarif || scan_exit=$?

echo "foxclaw scan exit code: ${scan_exit}"
if [ "${scan_exit}" -ne 0 ] && [ "${scan_exit}" -ne 2 ]; then
  exit "${scan_exit}"
fi

python - <<'PY'
import json
for path in ("foxclaw.json", "foxclaw.sarif"):
    with open(path, "r", encoding="utf-8") as handle:
        json.load(handle)
print("json+sarif parse ok")
PY
```

Generate deterministic snapshot output:

```bash
python -m foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --snapshot-out foxclaw.snapshot.json
```

Run with suppression policy overrides:

```bash
python -m foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --suppression-path suppressions/team-baseline.yml \
  --json
```

Compare snapshots:

```bash
python -m foxclaw snapshot diff \
  --before baseline.snapshot.json \
  --after current.snapshot.json \
  --json
```

Aggregate multiple profiles into fleet JSON:

```bash
python -m foxclaw fleet aggregate \
  --profile tests/fixtures/testbed/profile_baseline \
  --profile tests/fixtures/testbed/profile_weak_perms \
  --ruleset tests/fixtures/testbed/rulesets/integration.yml \
  --json
```

Orchestrate a live sync and deterministic scan wrapper:

```bash
python -m foxclaw live \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml
```

## Makefile Targets

Equivalent shortcuts.

```bash
make install
make lint
make typecheck
make test
make test-integration
make testbed-fixtures
make testbed-fixtures-write
make fixture-scan
make synth-profiles
make synth-profiles-bootstrap
make fuzz-profiles
make profile-fidelity
make extension-catalog
make verify
make verify-full
make dep-audit
make sbom
make sbom-verify
make certify
make certify-live
make test-firefox-container
make soak-smoke
make soak-smoke-fuzz1000
make soak-daytime
make soak-daytime-fuzz1000
make soak-daytime-detached
make soak-status
make soak-stop
make hooks-install
make clean
```

If Docker requires elevated access on your host:

```bash
make test-firefox-container DOCKER="sudo docker"
```

Run on-demand dependency vulnerability audit:

```bash
make dep-audit
```

Run trust-boundary CLI smoke checks:

```bash
make trust-smoke
```

Generate/update AMO extension catalog snapshot for realistic profile synthesis:

```bash
make extension-catalog
```

Run synth/fuzz runners directly with deterministic realism controls:

```bash
scripts/synth_runner.sh \
  --count 20 \
  --mode bootstrap \
  --seed 424242 \
  --mutation-budget 1 \
  --fidelity-min-score 70

scripts/fuzz_runner.sh \
  --count 1000 \
  --mode chaos \
  --seed 525252 \
  --mutation-budget 3 \
  --fidelity-min-score 50
```

Generated profile realism baseline now includes:

- Valid NSS stores (`key4.db`, `cert9.db`, `pkcs11.txt`)
- HSTS state file (`SiteSecurityServiceState.txt`) derived from HTTPS history hosts
- Web/app storage footprint under `storage/default/` (LocalStorage + IndexedDB)
- `favicons.sqlite` entries aligned to `places.sqlite` URLs

Packaging dry-run prior to release merges:

```bash
python -m pip install --upgrade build twine
rm -rf build dist
python -m build
python -m twine check dist/*
make sbom
make sbom-verify
```

## Review-Ready Gate Sequence

Use this exact sequence before pushing.

```bash
make certify
```

For milestone sign-off before push:

```bash
make certify-live
```

## Long-Run Soak

Run a local smoke soak (single cycle):

```bash
make soak-smoke SOAK_SUDO_PASSWORD='<sudo-password>'
```

Run the same smoke cycle with 1000 fuzzed profiles (high-memory hosts):

```bash
make soak-smoke-fuzz1000 SOAK_SUDO_PASSWORD='<sudo-password>'
```

Run the daytime burn-in gate used for commit confidence:

```bash
make soak-daytime SOAK_SUDO_PASSWORD='<sudo-password>'
```

Run the daytime burn-in with 1000 fuzzed profiles:

```bash
make soak-daytime-fuzz1000 SOAK_SUDO_PASSWORD='<sudo-password>'
```

Run the same daytime burn-in detached via user systemd:

```bash
make soak-daytime-detached SOAK_SUDO_PASSWORD='<sudo-password>'
make soak-status
make soak-stop
```

For overnight duration, run the harness directly:

```bash
systemd-run --user \
  --unit foxclaw-soak-overnight \
  --same-dir \
  --collect \
  --setenv=SOAK_SUDO_PASSWORD='<sudo-password>' \
  scripts/soak_runner.sh \
  --duration-hours 10 \
  --label overnight-phase1 \
  --output-root /var/tmp/foxclaw-soak
```

See `docs/SOAK.md` for artifact structure and failure triage workflow.

## Git Hook Setup

Install the pre-push hook once per clone:

```bash
make hooks-install
```

The hook runs `./scripts/certify.sh` before every push.

See `docs/QUALITY_GATES.md` for the full gate policy.

## Documentation Discipline

- Keep docs synchronized with runtime behavior.
- If command surfaces change, update:
  - `README.md`
  - `docs/ARCHITECTURE.md`
  - `docs/SECURITY_MODEL.md`
  - `docs/RULESET_TRUST.md` (when ruleset trust controls or manifest contract changes).
  - `docs/SBOM.md` (when release SBOM generation/verification behavior changes).
  - `docs/GITHUB_ACTIONS.md` (if CI behavior changed).
  - `docs/TESTBED.md` (if fixture or container testbed flows changed).
- For roadmap or strategic changes, update:
  - `docs/ROADMAP.md`
  - `docs/RESEARCH.md`
  - `docs/VULNERABILITY_INTEL.md`
  - `docs/QUALITY_GATES.md`.
  - `docs/PROFILE_REVIEW_CHECKLIST.md` (when profile realism/fidelity behavior changes).
- For profile realism work, keep one-source ownership clear:
  - `docs/PROFILE_HANDOFF.md` (first update for state/memory/anti-loop notes).
  - `docs/PROFILE_SYNTHESIS.md` (generator/runtime behavior changes).
  - `docs/PROFILE_FIDELITY_SPEC.md` (fidelity scoring/gate contract changes).
  - `docs/WORKSLICES.md` (status and deferred work changes).
  - `docs/MISTAKES.md` (new regressions and preventive actions).

## Packaging Notes

`pyproject.toml` follows PyPA guidance for project metadata, editable installs, package discovery, and tool configuration.

Primary packaging reference:

- https://packaging.python.org/en/latest/guides/writing-pyproject-toml/
