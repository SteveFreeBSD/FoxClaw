# FoxClaw: Agent Operating Rules (Codex)

This file defines how the agent must operate in this repository.
The goal is predictable progress, minimal churn, and deterministic behavior.

## 0) Prime directive
Work one workslice at a time.
Do not expand scope.
If you see additional issues, write them down in the end-of-slice checkpoint under risks or next actions.

## 1) Sources of truth for planning and ordering
- Canonical docs map: docs/INDEX.md
- Workslice queue and status: docs/WORKSLICES.md
- Roadmap narrative: docs/ROADMAP.md
- CLI behavior and exit-code contract: docs/CLI_CONTRACT.md
- If docs/WORKSLICES.md contains a "Current Direction" section, it overrides numeric ordering.
- If there is a pre-merge queue file (example: PREMERGE_READINESS.md), follow it only if WORKSLICES.md points to it.
- When docs conflict, resolve in this order:
  1) docs/CLI_CONTRACT.md
  2) docs/WORKSLICES.md
  3) docs/ROADMAP.md
- If PREMERGE_READINESS.md queue text conflicts with WORKSLICES.md status/order, follow WORKSLICES.md and log doc drift in checkpoint risks or next actions.

## 2) Workslice execution loop
For each workslice, follow this exact loop.

### 2.0 Session bootstrap (before selecting work)
Run:
- python scripts/session_memory.py show
- git status --short

Read:
- docs/WORKSLICES.md (Current Direction first)
- docs/PREMERGE_READINESS.md (merge-hold context only)

### 2.1 Start-of-slice memory recall (before any edits)
Run:
- python scripts/memory_index.py update || python scripts/memory_index.py build

Query memory using a phrase query for hyphenated IDs:
- python scripts/memory_query.py '"WS-XX"' --limit 8
- python scripts/memory_query.py '"<feature keywords>"' --limit 8

Then write a short "Constraints from memory" section in your plan using the top hits.

If the target slice appears already implemented, validate with code/tests and convert the slice to a status-reconciliation docs update instead of re-implementing behavior.

### 2.2 Quote scope verbatim
Quote the workslice scope lines verbatim from docs/WORKSLICES.md.
If the workslice has no explicit acceptance criteria, use the repo-wide rule:
- Every changed behavior must be covered by deterministic assertions.

### 2.3 Definition of done
Write 4 to 7 testable bullets.
Each bullet must be verifiable via a command or a deterministic assertion.

### 2.4 Minimal touch list
List exact files you intend to touch before editing.
Keep the list small.
If it grows, stop and re-plan.

### 2.5 Implement
Implement only what the workslice requires.
Prefer small diffs.
Prefer deterministic logic, deterministic ordering, and stable schema fields.

### 2.6 Verification
Run the smallest verification that proves the workslice.
Default:
- .venv/bin/pytest -q

If the slice touches a specific subsystem, run its focused tests as well.

If certify is part of the repo workflow and is fast enough, you may run it, but do not edit certify scripts unless the workslice explicitly demands it.

### 2.7 End-of-slice memory checkpoint (after tests pass)
Record a checkpoint:
- python scripts/session_memory.py checkpoint --focus "<WS-XX: summary>" --next "<next>" --risks "<risks>" --decisions "<decisions>"

Then refresh index:
- python scripts/memory_index.py update || python scripts/memory_index.py build

Expected side effect: artifacts/session_memory/SESSION_MEMORY.jsonl and
artifacts/session_memory/SESSION_MEMORY.md will usually change locally.

### 2.8 Stop condition
Stop after completing one workslice unless the user explicitly says to continue.

## 3) Strict scope guardrails
### 3.1 Do not touch these unless the workslice explicitly requires it
- .github/workflows/*
- scripts/certify.sh
- repo-wide docs (README.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md)
- release automation files
- large refactors or formatting-only sweeps

If you believe a change is necessary but not in scope, put it in risks/next actions, do not implement.

### 3.2 Determinism rules
All new behavior must be deterministic given identical inputs.
All new outputs must have deterministic ordering (sort keys explicitly).
Tests must avoid time dependence unless time is explicitly a feature.
When writing timestamps, prefer explicit fixtures in tests.

### 3.3 Artifacts and generated files
Do not commit generated artifacts.
Typical examples:
- artifacts/
- evidence bundles
- SQLite indexes

If tests generate artifacts, remove them before finishing the slice or ensure they are ignored.

## 4) Testing and evidence discipline
- New behavior requires new tests.
- Tests must be stable across platforms when feasible.
- If a test needs a fixture, prefer an explicit fixture file in tests/fixtures with deterministic contents.
- If the workslice changes any contract or schema, add a deterministic contract assertion.

## 5) Documentation edits
Docs can be updated only when one of these is true:
- The workslice explicitly requires documentation changes.
- The behavior has changed and docs would otherwise be inaccurate.
- Updating docs/WORKSLICES.md status for the workslice you just completed.

Docs updates should be minimal and tied directly to the slice.

## 6) Git discipline
- Keep commits small and tied to a single workslice.
- Do not mix unrelated changes.
- Before stopping, show:
  - git status --short
  - git diff --stat

If the user asked not to push, do not push.

## 7) Safe interaction rules
If you are uncertain about scope, ask before editing.
If a command fails, report the raw error and your smallest proposed fix.
Avoid broad "cleanup" commits.
