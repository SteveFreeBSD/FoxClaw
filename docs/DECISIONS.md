# Decisions (ADR Style)

## ADR-0001: Language and Runtime
- Status: Accepted
- Decision: Python >= 3.12.
- Rationale: Strong stdlib for filesystem/INI/SQLite/HMAC; fast iteration and testability.

## ADR-0002: CLI Framework
- Status: Accepted
- Decision: Typer for CLI.
- Rationale: Type-driven command ergonomics and clean command grouping.

## ADR-0003: Data Models
- Status: Accepted
- Decision: Pydantic models for stable report/snapshot schemas.
- Rationale: Validation + explicit schemas for deterministic outputs.

## ADR-0004: Report Channels
- Status: Accepted
- Decision: Rich for terminal output; JSON + SARIF for machine integrations.
- Rationale: Human readability + automation interoperability.

## ADR-0005: Ruleset Format
- Status: Accepted
- Decision: YAML rulesets with version metadata and constrained DSL.
- Rationale: Readable, reviewable policy surface with bounded complexity.

## ADR-0006: Safety Model
- Status: Accepted
- Decision: Strict two-phase plan/apply with explicit flags and confirmation.
- Rationale: Prevent accidental system/profile changes and preserve trust boundary.

## ADR-0007: Runtime Network Policy
- Status: Accepted
- Decision: No network access in normal runtime code paths.
- Rationale: Determinism, privacy, and reproducibility.

## ADR-0008: Profile Selection Strategy
- Status: Accepted
- Decision: Prefer lock-indicated active profile; otherwise deterministic score from `.default-release`, `Default=1`, `places.sqlite` size, and profile dir mtime.
- Rationale: Combines operational signal (active lock) with stable heuristics from Mozilla profile behavior.

## ADR-0009: Collector Trust Boundary
- Status: Accepted
- Decision: Collectors are read-only and side-effect free; remediation code lives in separate modules/paths.
- Rationale: Aligns with audit-first tools (Lynis/OpenSCAP style) and reduces accidental mutation risk.

## ADR-0010: Output Determinism
- Status: Accepted
- Decision: Keep internal findings schema canonical and map to text/JSON/SARIF with stable field ordering.
- Rationale: Enables drift detection, CI integration, and reproducible scans.
