# Contributing

## Local Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --requirement requirements-dev.lock
```

## Local Gates

Baseline assurance gate:

```bash
./scripts/certify.sh
```

Evidence gate:

```bash
./scripts/certify.sh --emit-evidence-bundle
```

Focused policy/test gates:

```bash
.venv/bin/pytest -q tests/test_cli_exit_codes.py -k "live_rejects"
python scripts/check_ci_supply_chain.py
.venv/bin/pytest -q
```

## Pull Request Expectations

- Keep changes small, scoped, and reviewable.
- Include or update tests for behavior-affecting changes.
- Run relevant gates before opening the PR.
- Update canonical docs when contracts or operator workflows change.
- Avoid drive-by refactors in unrelated areas.
