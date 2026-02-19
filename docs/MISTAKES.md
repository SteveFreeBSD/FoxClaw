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
- Date: 2026-02-19
  Mistake: while refactoring M3.1 output consistency, provisional `ScanSummary` construction omitted required `high_findings_count`.
  Impact: scan command returned operational exit `1` with Pydantic validation error until corrected.
  Prevention: keep intermediate model instances schema-complete during staged construction, and run CLI-path tests immediately after model-field refactors.
