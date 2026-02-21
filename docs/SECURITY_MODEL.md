# Security Model

## Security Invariants

These are non-negotiable for the scan runtime:

- Offline-by-default.
  - No network calls during scan collection/evaluation/reporting.
- Read-only collection.
  - Collectors never mutate host/profile state.
- Boundary separation.
  - Collection, rule evaluation, and reporting remain isolated concerns.
- Deterministic contracts.
  - Stable sorting and schemas for machine consumers and CI.
  - Fleet aggregation identities are deterministic hashes over local host/profile metadata.

## Trust Boundaries

### Evidence Boundary (`foxclaw/collect/*`, `foxclaw/profiles.py`)

- Inputs: local filesystem artifacts and SQLite databases.
- Allowed: read-only open/stat/query operations.
- Disallowed: write, chmod/chown, profile config mutation, process control.

### Evaluation Boundary (`foxclaw/rules/*`)

- Inputs: evidence models and declarative rulesets.
- Allowed: deterministic finding evaluation and suppression-policy matching.
- Disallowed: host mutation and network operations.

### Reporting Boundary (`foxclaw/report/*`)

- Inputs: findings and evidence models.
- Allowed: text/JSON/SARIF rendering.
- Disallowed: extra collection, remediation actions, network transmission.

### Remediation Boundary (future phase)

- Kept isolated from scan runtime by design.
- Not shipped in the current CLI runtime surface.

## Threat Model (Current)

- Malicious or malformed local artifacts.
  - Control: strict parsing, typed models, and fail-closed operational errors.
- Live profile race conditions.
  - Control: lock detection and optional `--require-quiet-profile` gate.
- Ruleset drift or inconsistent outputs across runs.
  - Control: deterministic ordering and versioned rulesets.
- CI token misuse for SARIF upload.
  - Control: job-scoped `security-events: write` and fork PR upload skip logic.
- Release publishing misuse.
  - Control: OIDC trusted publishing + environment-scoped release workflow + provenance attestation.

## Data Handling

- Inputs are local machine artifacts only.
- Output payloads may contain local file paths and evidence text.
- Fleet aggregation payloads include host/profile identity hashes for downstream joins.
- Operators should treat JSON/SARIF artifacts as potentially sensitive operational telemetry.

## Operational Assumptions

- Scan may run against active profiles unless `--require-quiet-profile` is set.
- SQLite integrity checks use read-only URI mode.
- Runtime does not persist hidden state beyond explicit output files.
- Network-backed intel updates run only through explicit `intel sync`; HTTPS is default,
  and plaintext HTTP requires explicit `--allow-insecure-http` opt-in.

## Forward Security Backlog

- Signed policy packs and manifest verification.
- Snapshot/diff integrity with hash-bound baselines.
- Suppression governance extensions (approval workflows and tighter scope controls).
- Continuous verification of release attestations in downstream deployment pipelines.
- Ongoing hardening for multi-source CVE/KEV/EPSS ingestion integrity and provenance policy.
- Any network-backed intelligence refresh must run in explicit update commands, never scan runtime.

## References

- NIST Secure Software Development Framework (SP 800-218):
  - https://csrc.nist.gov/pubs/sp/800/218/final
- GitHub SARIF upload permission model:
  - https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
