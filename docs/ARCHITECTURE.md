# Architecture

## Module Map
- `foxclaw/cli.py`: command surface and orchestration.
- `foxclaw/profiles.py`: profile discovery, scoring, and selection reasoning.
- `foxclaw/collect/*`: evidence collectors (read-only).
- `foxclaw/rules/*`: DSL and engine for posture checks.
- `foxclaw/report/*`: Rich text, JSON, SARIF emitters.
- `foxclaw/state/*`: snapshot serialization/signing and drift comparison.
- `foxclaw/rulesets/*.yml`: ruleset definitions.

## High-Level Data Flow
1. Resolve candidate Firefox profiles.
2. Select target profile (deterministic, reasoned metadata).
3. Collect evidence from local artifacts in read-only mode.
4. Evaluate rules against evidence to produce findings.
5. Emit report formats.
6. Optional: persist signed snapshots and perform drift diff.
7. Optional: produce remediation plan; apply only in explicit apply path.

## Trust Boundary Enforcement
- Collection APIs expose data-only models.
- Planning APIs consume findings and emit proposed actions.
- Apply APIs consume plan artifacts; collection modules are not imported into mutation subroutines.
