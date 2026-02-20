# FoxClaw

FoxClaw is a deterministic, read-only Firefox security posture scanner for Linux.

## Current Scope

- Deterministic Firefox profile discovery and selection.
- Read-only evidence collection from:
  - preference files (`prefs.js`, `user.js`)
  - sensitive profile file permissions
  - enterprise policy files
  - extension inventory and manifest permission posture (`extensions.json`, `extensions/`)
    - extensions are classified by source (`profile`, `system`, `builtin`, etc.)
    - unsigned/risk checks default to profile-controlled extensions (system/builtin excluded)
  - SQLite quick integrity checks (`PRAGMA quick_check`)
- Declarative rule evaluation from versioned YAML rulesets.
- Output renderers for terminal, JSON, and SARIF 2.1.0.

## Security Boundary

- Collection is read-only and side-effect free.
- Runtime scanning is offline-by-default (no network calls).
- Remediation is intentionally out of scope for the current CLI surface.

See `docs/SECURITY_MODEL.md` for the complete trust model.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
foxclaw --help
```

## Usage

List discovered profiles:

```bash
foxclaw profiles list
```

Scan a profile to JSON:

```bash
foxclaw scan --profile tests/fixtures/firefox_profile --json
```

Write JSON and SARIF artifacts:

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --output foxclaw.json \
  --sarif-out foxclaw.sarif
```

Write a deterministic baseline snapshot artifact:

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --snapshot-out foxclaw.snapshot.json
```

Compare snapshots for deterministic drift detection:

```bash
foxclaw snapshot diff \
  --before baseline.snapshot.json \
  --after current.snapshot.json \
  --json
```

Override enterprise policy discovery paths (repeatable):

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --policy-path /etc/firefox/policies/policies.json \
  --json
```

## Exit Codes

Canonical CLI contract:

- `0`: scan completed and emitted no `HIGH` findings.
- `1`: operational error (invalid input, IO failure, invalid flag combinations).
- `2`: scan completed and emitted one or more `HIGH` findings.

## SARIF and GitHub Code Scanning

- FoxClaw emits SARIF 2.1.0 (`--sarif`, `--sarif-out`).
- CI uploads SARIF via `github/codeql-action/upload-sarif@v4`.
- Upload requires `security-events: write`.
- Fork-origin pull requests safely skip upload when that permission is unavailable.

See `docs/SARIF.md` and `docs/GITHUB_ACTIONS.md`.

## Documentation Map

- `docs/ARCHITECTURE.md`: runtime boundaries and extension points.
- `docs/SECURITY_MODEL.md`: trust boundary, threat model, and safety invariants.
- `docs/SARIF.md`: SARIF schema mapping and GitHub ingestion constraints.
- `docs/ROADMAP.md`: phased delivery plan for next-level capabilities.
- `docs/RESEARCH.md`: source-backed research matrix for priority components.
- `docs/VULNERABILITY_INTEL.md`: Mozilla CVE and extension intelligence integration strategy.
- `docs/QUALITY_GATES.md`: milestone gate policy and pre-push certification flow.
- `docs/DEVELOPMENT.md`: local setup and quality gates.
- `docs/TESTBED.md`: deterministic Firefox testbed fixtures and container smoke lane.

## License

MIT. See `LICENSE`.
