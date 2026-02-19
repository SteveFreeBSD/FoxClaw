# FoxClaw Engineering Agent Rules

## Mission
Build FoxClaw as a Linux-focused Firefox security posture agent with deterministic, offline-by-default behavior and read-only evidence collection.

## Operating Rules
- Keep runtime offline by default; no network calls during scan/snapshot/diff/plan.
- Preserve a strict trust boundary:
  - Evidence collection modules are read-only.
  - Remediation actions are isolated and only invoked in apply mode.
- Two-phase change control:
  - `plan` generates actionable remediation plans.
  - `apply` requires explicit opt-in flags and confirmation unless waived.
- Favor deterministic outputs and stable schemas.
- Prefer small, test-backed milestones.

## Delivery Process
1. Research and document decisions before major implementation.
2. Implement one milestone at a time with tests.
3. Record each milestone in `docs/TASKLOG.md`.
4. Track mistakes and prevention actions in `docs/MISTAKES.md`.

## Quality Gate
- All new behavior covered by focused unit tests.
- CLI flows return clear exit codes and machine-readable outputs where applicable.
- No side effects in scan paths.
