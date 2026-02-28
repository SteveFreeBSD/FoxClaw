# Codex Workflow

Codex is most effective in this repository when work is slice-based, state is checkpointed, and outputs are machine-verifiable.

## Daily Loop

```bash
python scripts/session_memory.py show
git status --short
python scripts/check_mistakes_hygiene.py --base-ref origin/main
```

For a meaningful work block, checkpoint before stopping:

```bash
python scripts/session_memory.py checkpoint \
  --focus "<what changed>" \
  --next "<next concrete action>"
```

## Memory Recall

Session memory is local-only and stored under ignored `artifacts/session_memory/`.

Build a local-first recall index from that local journal:

```bash
python scripts/memory_index.py build
```

Refresh the index when the journal changes:

```bash
python scripts/memory_index.py update
```

Query relevant prior context:

```bash
python scripts/memory_query.py "certify"
```

## High-Leverage Patterns

- Keep repo instructions in `AGENTS.md` short and operational; push deep detail into docs.
- Use nested `AGENTS.md` only for true subdomain overrides (for example, under `docs/` or `scripts/`).
- Use non-interactive Codex runs for deterministic outputs in automation:

```bash
codex exec --json "<task>"
codex exec --output-schema path/to/schema.json "<task>"
```

- Capture hard gates in the prompt itself so Codex verifies before stopping:
  - `python scripts/check_ci_supply_chain.py`
  - `python scripts/check_mistakes_hygiene.py --base-ref origin/main`
  - `python scripts/session_memory.py validate`
  - `python scripts/memory_index.py build`
  - `.venv/bin/pytest -q`
  - `./scripts/certify.sh --emit-evidence-bundle`

## Slice Prompt Template

Use this as a starting prompt for implementation slices:

```text
Goal: <single outcome>
Scope: <exact files or components>
Constraints: minimal diffs, no refactor, preserve CLI/exit contracts
Acceptance gates:
1) <command>
2) <command>
Deliverable: applied changes + command results
```

## Recommended Local Codex Config

Set in `~/.codex/config.toml`:

```toml
project_doc_fallback_filenames = ["AGENTS.md", "docs/CODEX_WORKFLOW.md", "docs/INDEX.md"]
project_doc_max_bytes = 65536
```

This keeps instruction discovery predictable and avoids context drift in larger sessions.

## Official References

- Codex CLI/config: <https://developers.openai.com/codex/config>
- AGENTS instructions: <https://developers.openai.com/codex/config#agentsmd-instructions-file>
- Non-interactive mode: <https://developers.openai.com/codex/non-interactive>
- Skills: <https://developers.openai.com/codex/skills>
- GitHub Action: <https://developers.openai.com/codex/github-actions>
