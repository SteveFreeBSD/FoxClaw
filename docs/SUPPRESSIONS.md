# Suppressions

FoxClaw supports deterministic suppression policies via `--suppression-path`.

Use this for controlled, auditable exceptions where a finding is temporarily accepted.

## Invariants

- Suppressions are offline and file-driven.
- Every suppression requires:
  - `rule_id`
  - `scope`
  - `owner`
  - `reason`
  - `expires_at` (timezone-aware timestamp)
- Expired suppressions never apply.
- Matching is deterministic by suppression file path and rule metadata ordering.

## Policy Schema

```yaml
schema_version: "1.0.0"
suppressions:
  - id: "example-001"               # optional
    rule_id: "FC-STRICT-EXT-001"    # required
    owner: "security-team"          # required
    reason: "Lab-only temporary extension package under review."  # required
    expires_at: "2026-06-30T00:00:00+00:00"                       # required
    scope:                                                      # required
      profile_glob: "/home/*/.mozilla/firefox/*"
      evidence_contains: "unsigned@example.com"                # optional
```

## CLI Usage

Single policy file:

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/strict.yml \
  --suppression-path suppressions/team-baseline.yml \
  --json
```

Multiple policy files (repeatable):

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --suppression-path suppressions/team-baseline.yml \
  --suppression-path suppressions/lab-overrides.yml \
  --json
```

## Output Contract

- Suppressed findings are excluded from `findings`.
- `summary.findings_suppressed_count` reports how many findings were suppressed.
- `suppressions.applied` records applied suppression metadata.
- `suppressions.expired` records suppressions that were loaded but already expired.

## Failure Behavior

Invalid suppression files fail closed as operational errors (`exit 1`), including:

- missing required fields
- empty `rule_id` / `owner` / `reason` / `scope.profile_glob`
- `expires_at` without a timezone offset
