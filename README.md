# FoxClaw

FoxClaw is a deterministic, read-only Firefox security posture scanner for Linux.

## What It Does

- Discovers Firefox profiles with deterministic selection rules.
- Collects local evidence in read-only mode:
  - preferences (`prefs.js`, `user.js`)
  - sensitive file permissions
  - enterprise policy files
  - SQLite `PRAGMA quick_check` health
- Evaluates findings with versioned YAML rulesets.
- Emits terminal, JSON, and SARIF 2.1.0 reports.

## Trust Boundary

- Evidence collection is read-only and side-effect free.
- Remediation is intentionally out of scope for the current CLI surface.
- Scan paths are offline-by-default (no runtime network calls).

See `docs/SECURITY_MODEL.md` for the full model.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
foxclaw --help
```

## Examples

List discovered profiles:

```bash
foxclaw profiles list
```

Scan a profile and print JSON:

```bash
foxclaw scan --profile tests/fixtures/firefox_profile --json
```

Write both JSON and SARIF artifacts:

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --output foxclaw.json \
  --sarif-out foxclaw.sarif
```

## Exit Codes

This is the canonical exit-code contract for CLI automation:

- `0`: scan completed and no `HIGH` findings were emitted.
- `1`: operational error (invalid input, IO failure, mutually exclusive flags, etc.).
- `2`: scan completed and emitted one or more `HIGH` findings.

## SARIF + GitHub Code Scanning

- FoxClaw emits SARIF 2.1.0 (`--sarif`, `--sarif-out`).
- The repository workflow uploads SARIF with `github/codeql-action/upload-sarif`.
- The upload job requires `security-events: write` and is skipped for fork-origin pull requests where that permission is unavailable.

See `docs/SARIF.md` and `docs/GITHUB_ACTIONS.md`.

## Development

Developer setup, lint/type gates, and verification commands are in `docs/DEVELOPMENT.md`.

## License

MIT. See `LICENSE`.
