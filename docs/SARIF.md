# SARIF Output

FoxClaw emits deterministic SARIF 2.1.0 for GitHub Code Scanning and other SARIF consumers.

## Primary Specifications

- OASIS SARIF 2.1.0 standard:
  - https://www.oasis-open.org/standard/sarifv2-1-os/
- OASIS SARIF schema:
  - https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
- GitHub SARIF upload guide:
  - https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
- GitHub SARIF support and limits:
  - https://docs.github.com/en/code-security/reference/code-scanning/sarif-support-for-code-scanning

## Schema Shape (Emitted)

- Top level:
  - `version: "2.1.0"`
  - `$schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`
  - `runs: [...]`
- `runs[0].tool.driver`:
  - `name`, `version`, `semanticVersion`
  - `rules[]` (stable ids and metadata).
- `runs[0].results[]`:
  - `ruleId`, `ruleIndex`, `level`, `message.text`
  - `locations[].physicalLocation.artifactLocation.uri`
  - `partialFingerprints` for stable alert identity.

## FoxClaw Finding Mapping

- `Finding.id` -> `rules[].id`, `results[].ruleId`.
- `Finding.title` -> `rules[].name`, `rules[].shortDescription.text`.
- `Finding.rationale` -> `rules[].fullDescription.text`.
- `Finding.recommendation` -> `rules[].help.text`.
- `Finding.severity` -> `results[].level`, `rules[].defaultConfiguration.level`.
- `Finding.evidence` -> `results[].message.text`, `results[].properties.evidence`.
- normalized evidence path -> `artifactLocation.uri`.

## Severity Mapping

- `HIGH` -> `error`.
- `MEDIUM` -> `warning`.
- `INFO` -> `note`.

Additional metadata in `properties`:

- `security-severity` (string score).
- `category`.
- `confidence`.
- `foxclawSeverity`.
- `tags`.

## Determinism Rules

- JSON keys emitted with stable ordering.
- Rules deduplicated and sorted by rule id.
- Results sorted by severity then rule id.
- `artifactLocation.uri` normalized for path stability.
- Stable `partialFingerprints` derived from rule id, artifact URI, and normalized evidence lines.

## GitHub Ingestion Constraints (Important)

From current GitHub SARIF support docs:

- gzip-compressed SARIF upload max size: 10 MB.
- max runs per file: 20.
- max results per run: 25,000 (top 5,000 displayed).
- max rules per run: 25,000.

Operational implication:

- Keep result cardinality controlled.
- Keep paths and rule ids deterministic to avoid alert churn.
- Use upload categories consistently when uploading multiple SARIF files for the same commit.

## Validation and Tests

- FoxClaw validates SARIF against the official SARIF Draft-04 schema in `tests/test_sarif_m4.py`.
- Validation schema is vendored at `tests/schemas/sarif-schema-2.1.0.json`.

Local parse check:

```bash
python - <<'PY'
import json
json.load(open("foxclaw.sarif", "r", encoding="utf-8"))
print("sarif parse ok")
PY
```

## Rule Help URI Convention

Each rule uses:

- `helpUri: docs/SARIF.md#rule-<rule-id-slug>`.

This keeps rule links deterministic across environments.
