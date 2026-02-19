# Project Charter

## Scope
FoxClaw audits Firefox posture on Linux by collecting local evidence, evaluating posture rules, and supporting drift tracking with signed snapshots.

## In Scope
- Profile discovery and selection reasoning.
- Read-only collectors for prefs, policies, addons metadata, filesystem permissions, and SQLite health checks.
- Rules evaluation and findings generation.
- Reports: terminal text, JSON, SARIF.
- Snapshot signing and diff.
- Plan/apply workflow with explicit safety gates.

## Non-Goals
- Endpoint management at scale.
- Full Firefox policy enforcement framework.
- Cross-browser support.
- Live network reputation checks during runtime scans.

## Threat Model (Initial)
- Misconfigured prefs or policy drift.
- Risky third-party extensions.
- Weak filesystem permissions on profile/security-relevant files.
- Corrupted profile SQLite stores affecting integrity signals.
- Unsafe automation applying changes without explicit operator intent.

## Trust Boundary
- **Evidence boundary:** discovery + collectors + rules input are read-only and must not modify host/profile state.
- **Action boundary:** remediation is a separate phase and code path, executed only by `apply` with explicit flags/confirmation.
- Artifacts (reports/snapshots/plans) are outputs, not direct mutators.
