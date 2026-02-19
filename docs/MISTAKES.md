# Mistakes and Preventive Actions

## Format
- Date:
- Mistake:
- Impact:
- Prevention:

## Entries
- Date: 2026-02-19
  Mistake: initial setuptools auto-discovery unintentionally included `agents/` as a top-level package.
  Impact: editable install failed, blocking test execution.
  Prevention: pin package discovery in `pyproject.toml` to `foxclaw*` via `[tool.setuptools.packages.find]`.
