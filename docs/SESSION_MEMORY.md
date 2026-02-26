# Session Memory

Persistent handoff context between sessions.

## Usage

```bash
python scripts/session_memory.py show
python scripts/session_memory.py checkpoint \
  --focus "<what changed>" \
  --next "<next action>"
```

## Current Snapshot

- Updated: 2026-02-26T21:38:29.766395+00:00
- Branch: docs/windows-profile-gen
- Commit: `34f637cbbdacc1b1d6e610f862581266e6f56038`
- Focus: Integrated session-memory and mistakes-hygiene gates into certify/CI/docs
- Next: Run full gate suite and publish workflow tips
- Risks: Strict hygiene checks may need occasional [no-mistake-entry] bypass
- Decisions: Track journal in docs/SESSION_MEMORY.jsonl so context persists across sessions

## Recent Checkpoints

### 2026-02-26T21:38:29.766395+00:00
- Branch: docs/windows-profile-gen
- Commit: `34f637cbbdacc1b1d6e610f862581266e6f56038`
- Focus: Integrated session-memory and mistakes-hygiene gates into certify/CI/docs
- Next: Run full gate suite and publish workflow tips
- Risks: Strict hygiene checks may need occasional [no-mistake-entry] bypass
- Decisions: Track journal in docs/SESSION_MEMORY.jsonl so context persists across sessions
