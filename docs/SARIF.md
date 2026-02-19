# SARIF Output

FoxClaw emits SARIF 2.1.0 for GitHub Code Scanning and generic SARIF consumers.

## Specifications

Primary references used for implementation:

- OASIS SARIF 2.1.0 standard:
  - https://www.oasis-open.org/standard/sarifv2-1-os/
- OASIS SARIF 2.1.0 schema:
  - https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
- GitHub upload guidance:
  - https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
- GitHub SARIF support limits:
  - https://docs.github.com/en/code-security/reference/code-scanning/sarif-support-for-code-scanning

## Field Mapping

FoxClaw finding fields map to SARIF as follows:

- `Finding.id` -> `result.ruleId`, `tool.driver.rules[].id`
- `Finding.title` -> `rules[].name`, `rules[].shortDescription.text`
- `Finding.rationale` -> `rules[].fullDescription.text`
- `Finding.recommendation` -> `rules[].help.text`
- `Finding.severity` -> `result.level` and `rules[].defaultConfiguration.level`
- `Finding.evidence` -> `result.message.text`, `result.properties.evidence`
- Extracted evidence path -> `result.locations[].physicalLocation.artifactLocation.uri`

## Severity Mapping

- `HIGH` -> `error`
- `MEDIUM` -> `warning`
- `INFO` -> `note`

Additional GitHub-friendly metadata is included in `properties`:

- `security-severity` (stringified score)
- `tags`
- `category`
- `confidence`

## Determinism Guarantees

- Top-level payload is emitted with sorted keys.
- Rules are deduplicated and sorted by rule id.
- Results are sorted deterministically by severity then rule id.
- Stable `partialFingerprints` are derived from rule id, normalized artifact URI, and evidence text.
- Artifact paths are normalized:
  - repo-relative when possible
  - otherwise profile-relative when possible
  - absolute path only when no safe relative base applies

## Rule Help URI Convention

Each rule entry includes:

- `helpUri: docs/SARIF.md#rule-<rule-id-slug>`

This provides a stable, deterministic URI value for SARIF consumers.

## Example

```bash
foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --sarif-out foxclaw.sarif
```

FoxClaw validates SARIF generation against the official SARIF 2.1.0 schema in `tests/test_sarif_m4.py` using `tests/schemas/sarif-schema-2.1.0.json`.

## Rule Reference Anchors

### Rule: FC-PREF-001

### Rule: FC-PREF-002

### Rule: FC-FILE-001

### Rule: FC-FILE-002

### Rule: FC-POLICY-001

### Rule: FC-SQL-001

### Rule: FC-SQL-002

### Rule: FC-STRICT-PREF-001

### Rule: FC-STRICT-PREF-002

### Rule: FC-STRICT-FILE-001

### Rule: FC-STRICT-FILE-002

### Rule: FC-STRICT-POLICY-001

### Rule: FC-STRICT-SQL-001

### Rule: FC-STRICT-SQL-002
