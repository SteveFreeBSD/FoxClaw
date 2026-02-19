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
pytest -q
ruff check .
mypy foxclaw
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

## Makefile Targets

Equivalent shortcuts.

```bash
make install
make lint
make typecheck
make test
make fixture-scan
make verify
make clean
```

## Review-Ready Gate Sequence

Use this exact sequence before pushing.

```bash
make lint
make typecheck
make test
make fixture-scan
make clean
```

## Documentation Discipline

- Keep docs synchronized with runtime behavior.
- If command surfaces change, update:
  - `README.md`
  - `docs/ARCHITECTURE.md`
  - `docs/SECURITY_MODEL.md`
  - `docs/GITHUB_ACTIONS.md` (if CI behavior changed).
- For roadmap or strategic changes, update:
  - `docs/ROADMAP.md`
  - `docs/RESEARCH.md`.

## Packaging Notes

`pyproject.toml` follows PyPA guidance for project metadata, editable installs, package discovery, and tool configuration.

Primary packaging reference:

- https://packaging.python.org/en/latest/guides/writing-pyproject-toml/
