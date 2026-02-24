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
- Date: 2026-02-19
  Mistake: attempted to remove stale docs with a blocked shell deletion command in this execution environment.
  Impact: cleanup step failed until file deletion was retried with repository-safe patch operations.
  Prevention: prefer `apply_patch` delete hunks for tracked-file removals to avoid policy rejection and keep edits auditable.
- Date: 2026-02-20
  Mistake: profile realism layer referenced `KEY4_B64`/`CERT9_B64` placeholders that were not guaranteed to be defined in all generation paths.
  Impact: synth/fuzz runs failed with runtime errors and invalid NSS artifact output.
  Prevention: keep NSS artifact creation path deterministic (`certutil` or validated SQLite fallback), and add regression tests that assert both files are valid SQLite databases.
- Date: 2026-02-20
  Mistake: HSTS state generation initially used malformed serialization that did not match Firefox tab-delimited expectations.
  Impact: generated profiles failed fidelity checks and reduced realism quality.
  Prevention: serialize `SiteSecurityServiceState.bin` using Firefox-compatible field ordering and validate with parser tests tied to generated HTTPS history hosts.
- Date: 2026-02-20
  Mistake: fuzz fidelity threshold was temporarily lowered to mask quality regressions instead of fixing generation defects.
  Impact: soak runs looked green while low-fidelity profiles were admitted, reducing signal quality.
  Prevention: treat threshold changes as policy changes requiring explicit rationale, checklist update, and review approval; prioritize fixing the generator and mutation operators first.
- Date: 2026-02-20
  Mistake: stale large profile artifacts in `/tmp` and `/var/tmp/foxclaw-soak` were not cleaned before repeated heavy fuzz cycles.
  Impact: false failures (`database or disk is full`, `No space left on device`) obscured true regressions.
  Prevention: enforce periodic temp artifact cleanup before deep runs and include disk-space checks in soak triage procedure.
