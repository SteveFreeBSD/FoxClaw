# Development

## Environment Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e '.[dev]'
```

## Local Verification Commands

Run from repository root:

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

## Makefile Targets

Equivalent shortcuts:

```bash
make install
make lint
make typecheck
make test
make fixture-scan
make verify
make clean
```

## Packaging Notes

`pyproject.toml` follows PyPA guidance for:

- project metadata (`[project]`)
- editable/dev installs (`.[dev]`)
- setuptools package discovery
- tool configuration (`pytest`, `ruff`, `mypy`)
