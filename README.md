# FoxClaw

FoxClaw is a deterministic, read-only Firefox security posture scanner for Linux.

## Current Scope

- Deterministic Firefox profile discovery and selection.
- Read-only evidence collection from:
  - preference files (`prefs.js`, `user.js`)
  - sensitive profile file permissions
  - enterprise policy files
  - profile artifact metadata (`handlers.json`, `containers.json`, `compatibility.ini`, etc.)
  - credential exposure signals (`logins.json`, `formhistory.sqlite`)
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

Stage and scan a Firefox profile copied from a Windows share or mounted SMB path:

```bash
foxclaw acquire windows-share-scan \
  --source-profile /mnt/forensics/FirefoxProfiles/jdoe.default-release \
  --ruleset foxclaw/rulesets/strict.yml \
  --output-dir /var/tmp/foxclaw-share-jdoe
```

Default behavior refuses active profile lock markers (`parent.lock`, `.parentlock`, `lock`).
Use `--allow-active-profile` only for validated crash-consistent captures.

Batch stage-and-scan many profile directories from one mounted share root:

```bash
foxclaw acquire windows-share-batch \
  --source-root /mnt/forensics/FirefoxProfiles \
  --staging-root /var/tmp/foxclaw-stage \
  --out-root /var/tmp/foxclaw-share-batch \
  --ruleset foxclaw/rulesets/strict.yml
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

### Architecture and Security

- `docs/ARCHITECTURE.md`: runtime boundaries and extension points.
- `docs/SECURITY_MODEL.md`: trust boundary, threat model, and safety invariants.
- `docs/WS24_LIVE_WORKFLOW_ARCHITECTURE.md`: `live` workflow orchestration design (sync + pinned scan).

### Research and Planning

- `docs/ROADMAP.md`: phased delivery plan (Phases 1–6, including 2.5 threat surface expansion and 2.6 adaptive intelligence).
- `docs/WORKSLICES.md`: ordered implementation slices (WS-01 through WS-56) with dependencies and acceptance criteria.
- `docs/RESEARCH.md`: source-backed research matrix for priority components (index of all research).
- `docs/RESEARCH_2026-02-20.md`: ecosystem alignment snapshot (Arkenfox, AMO, KEV/NVD feeds).
- `docs/RESEARCH_2026-02-22_RUST_APPLIANCE.md`: Rust appliance transition research (build hygiene, signed distribution, contracts).
- `docs/RESEARCH_2026-02-22_WINDOWS_SHARE_AUDIT.md`: enterprise Windows-share Firefox audit research and tactical controls.
- `docs/RESEARCH_2026-02-24_ADVERSARY_TESTBED.md`: adversary-profile testbed research baselines and harness integration.
- `docs/RESEARCH_2026-02-24_THREAT_SURFACE_EXPANSION.md`: threat surface gap analysis, CVE landscape, ATT&CK mappings, and self-learning architecture.
- `docs/VULNERABILITY_INTEL.md`: intelligence integration strategy (Mozilla CVE, NVD, KEV, EPSS, AMO, extension blocklist).

### Testing and Profiles

- `docs/TESTBED.md`: deterministic Firefox testbed fixtures and container smoke lane.
- `docs/PROFILE_SYNTHESIS.md`: profile generation architecture and runtime usage.
- `docs/PROFILE_FIDELITY_SPEC.md`: profile realism scoring contract and fidelity gate behavior.
- `docs/PROFILE_HANDOFF.md`: canonical profile-system onboarding, status memory, and anti-loop guardrails.
- `docs/PROFILE_REVIEW_CHECKLIST.md`: merge/CTO review checklist for profile realism changes.
- `docs/SOAK.md`: overnight soak execution and artifact analysis runbook.
- `docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md`: latest deep-soak outcomes, bottlenecks, and prioritized actions.
- `docs/SCAN_LEARNING_LOOP.md`: deterministic plan for learning from historical scan outputs.
- `docs/WINDOWS_SHARE_TESTING.md`: enterprise runbook for staged Firefox profile scans from Windows shares.

### Operations and Governance

- `docs/QUALITY_GATES.md`: milestone gate policy and pre-push certification flow.
- `docs/PREMERGE_READINESS.md`: expanded merge-hold checks and immediate planning queue.
- `docs/DEVELOPMENT.md`: local setup and quality gates.
- `docs/SUPPRESSIONS.md`: suppression policy schema, matching semantics, and governance usage.
- `docs/RULESET_TRUST.md`: ruleset trust-manifest schema, signature policy, and CLI usage.
- `docs/FLEET_OUTPUT.md`: multi-profile/fleet aggregation schema and versioning policy.
- `docs/MISTAKES.md`: post-incident log of past mistakes and preventive actions.

### Release and Compliance

- `docs/SARIF.md`: SARIF schema mapping and GitHub ingestion constraints.
- `docs/GITHUB_ACTIONS.md`: CI/CD workflow documentation and job descriptions.
- `docs/RELEASE_PROVENANCE.md`: release attestation and trusted-publishing verification runbook.
- `docs/SBOM.md`: CycloneDX SBOM generation/verification runbook for local and release workflows.
- `docs/DEPENDENCY_AUDIT.md`: scheduled dependency-vulnerability sweep workflow and triage runbook.

### Reviews (Historical)

- `docs/REVIEW_2026-02-20.md`: full-repo review findings and remediation status.

## License

MIT. See `LICENSE`.
