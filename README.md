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
    - unsigned/risk/debug checks default to profile-controlled extensions (system/builtin excluded)
  - suppression lifecycle (`--suppression-path`) with required owner/reason/expiration and scoped rule matching
  - SQLite quick integrity checks (`PRAGMA quick_check`)
- Declarative rule evaluation from versioned YAML rulesets.
- Optional ruleset trust verification via digest-pinned manifest entries, Ed25519 signatures,
  and multi-signature threshold/key-lifecycle policy.
- Offline intel correlation with deterministic multi-source merge metadata and finding-level
  risk priority fields (`risk_priority`, `risk_factors`).
- Offline extension reputation correlation from pinned AMO intelligence snapshots.
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

Aggregate multiple profiles into one normalized fleet contract:

```bash
foxclaw fleet aggregate \
  --profile tests/fixtures/testbed/profile_baseline \
  --profile tests/fixtures/testbed/profile_weak_perms \
  --ruleset tests/fixtures/testbed/rulesets/integration.yml \
  --json
```

Synchronize intelligence source materials into a local snapshot store:

```bash
foxclaw intel sync \
  --source mozilla=./intel/mozilla_firefox_advisories.v1.json \
  --source blocklist=./intel/blocklist.json \
  --json
```

Remote URL sources are fetched over HTTPS by default.  
Plain HTTP sources require explicit opt-in with `--allow-insecure-http`.

Run an offline scan correlated to a pinned intel snapshot:

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --intel-store-dir ~/.local/share/foxclaw/intel \
  --intel-snapshot-id latest \
  --json
```

Apply suppression policies (repeatable):

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --suppression-path suppressions/team-baseline.yml \
  --json
```

Verify ruleset trust from a pinned manifest (fail closed on mismatch):

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --ruleset-trust-manifest policies/ruleset-trust.yml \
  --require-ruleset-signatures \
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
- `docs/SOAK.md`: overnight soak execution and artifact analysis runbook.
- `docs/ROADMAP.md`: phased delivery plan for next-level capabilities.
- `docs/RESEARCH.md`: source-backed research matrix for priority components.
- `docs/RESEARCH_2026-02-20.md`: dated ecosystem alignment checkpoint (2026 snapshot).
- `docs/REVIEW_2026-02-20.md`: full-repo review findings and remediation status.
- `docs/WORKSLICES.md`: ordered implementation slices with dependencies and acceptance criteria.
- `docs/FLEET_OUTPUT.md`: multi-profile/fleet aggregation schema and versioning policy.
- `docs/RULESET_TRUST.md`: ruleset trust-manifest schema, signature policy, and CLI usage.
- `docs/RELEASE_PROVENANCE.md`: release attestation and trusted-publishing verification runbook.
- `docs/SBOM.md`: CycloneDX SBOM generation/verification runbook for local and release workflows.
- `docs/DEPENDENCY_AUDIT.md`: scheduled dependency-vulnerability sweep workflow and triage runbook.
- `docs/PREMERGE_READINESS.md`: expanded merge-hold checks and immediate planning queue.
- `docs/VULNERABILITY_INTEL.md`: Mozilla CVE and extension intelligence integration strategy.
- `docs/SUPPRESSIONS.md`: suppression policy schema, matching semantics, and governance usage.
- `docs/QUALITY_GATES.md`: milestone gate policy and pre-push certification flow.
- `docs/DEVELOPMENT.md`: local setup and quality gates.
- `docs/TESTBED.md`: deterministic Firefox testbed fixtures and container smoke lane.

## License

MIT. See `LICENSE`.
