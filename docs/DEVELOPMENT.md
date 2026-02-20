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
make verify
make verify-full
make certify
make certify-live
make test-firefox-container
make hooks-install
make clean
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
  - `docs/GITHUB_ACTIONS.md` (if CI behavior changed).
  - `docs/TESTBED.md` (if fixture or container testbed flows changed).
- For roadmap or strategic changes, update:
  - `docs/ROADMAP.md`
  - `docs/RESEARCH.md`
  - `docs/VULNERABILITY_INTEL.md`
  - `docs/QUALITY_GATES.md`.

## Packaging Notes

`pyproject.toml` follows PyPA guidance for project metadata, editable installs, package discovery, and tool configuration.

Primary packaging reference:

- https://packaging.python.org/en/latest/guides/writing-pyproject-toml/
