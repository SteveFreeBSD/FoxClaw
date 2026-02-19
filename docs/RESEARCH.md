# Research Matrix

This document tracks vital components needed to evolve FoxClaw beyond a baseline scanner.  
Use it as a decision log: each item has primary sources, adoption intent, and near-term action.

## Research Method

- Prefer standards bodies, official vendor docs, and maintainer-owned repositories.
- Record actionable constraints (size limits, permission boundaries, required fields).
- Add implementation decisions only after validating compatibility with FoxClaw trust boundaries.

## Component Priorities

### 1. SARIF Quality and Ingestion Reliability

- Why it matters:
  - SARIF is the machine contract for GitHub Code Scanning integration.
- Adoption intent:
  - preserve schema-clean SARIF with deterministic fingerprints and controlled result volume.
- Immediate actions:
  - enforce SARIF result/rule budgets before upload.
  - continue schema validation in tests.
- Primary sources:
  - https://www.oasis-open.org/standard/sarifv2-1-os/
  - https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
  - https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
  - https://docs.github.com/en/code-security/reference/code-scanning/sarif-support-for-code-scanning

### 2. Build Provenance and Artifact Attestation

- Why it matters:
  - lets consumers verify that releases came from expected CI workflows and source.
- Adoption intent:
  - emit attestations in GitHub Actions for release artifacts.
- Immediate actions:
  - add attestation step to release workflow.
  - document verification path for downstream users.
- Primary sources:
  - https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds
  - https://github.com/actions/attest-build-provenance

### 3. SLSA and in-toto Alignment

- Why it matters:
  - defines a measurable maturity model for software supply-chain security.
- Adoption intent:
  - map FoxClaw build/release controls to SLSA requirements incrementally.
- Immediate actions:
  - produce a controls-to-SLSA gap checklist.
  - attach provenance metadata to releases.
- Primary sources:
  - https://slsa.dev/spec/v1.2/
  - https://github.com/in-toto/attestation

### 4. Package Publishing Hardening (Python)

- Why it matters:
  - removes long-lived secrets and strengthens release authenticity.
- Adoption intent:
  - use PyPI Trusted Publishing when distribution is enabled.
- Immediate actions:
  - prepare OIDC-based publish workflow and dry-run in test index.
- Primary sources:
  - https://docs.pypi.org/trusted-publishers/using-a-publisher/
  - https://packaging.python.org/en/latest/guides/writing-pyproject-toml/

### 5. Dependency and Advisory Gates

- Why it matters:
  - blocks risky dependency changes early and keeps known vulnerabilities visible.
- Adoption intent:
  - gate pull requests with dependency review and scheduled vulnerability scans.
- Immediate actions:
  - add `actions/dependency-review-action` job.
  - add periodic `pip-audit` run.
- Primary sources:
  - https://github.com/actions/dependency-review-action
  - https://github.com/pypa/pip-audit
  - https://osv.dev/docs/

### 6. SBOM and Vulnerability Exchange

- Why it matters:
  - improves downstream transparency and enterprise adoption readiness.
- Adoption intent:
  - generate SBOM artifacts for releases and evaluate VEX support as needed.
- Immediate actions:
  - decide SPDX vs CycloneDX as canonical export format.
  - prototype SBOM generation in CI artifact stage.
- Primary sources:
  - https://spdx.dev/specifications/
  - https://cyclonedx.org/specification/overview/

### 7. Risk Prioritization Signals (KEV and EPSS)

- Why it matters:
  - helps rank findings with exploitability context instead of severity alone.
- Adoption intent:
  - support optional offline enrichment snapshots, never runtime network lookup.
- Immediate actions:
  - design enrichment cache format with source timestamp pinning.
  - define deterministic scoring merge rules.
- Primary sources:
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - https://www.first.org/epss/api
  - https://nvd.nist.gov/developers

### 8. Policy Engine Evolution (DSL + CEL/OPA Evaluation)

- Why it matters:
  - advanced users need expressive policy logic without rewriting collectors.
- Adoption intent:
  - keep current DSL as stable baseline and evaluate optional advanced engines behind a strict adapter boundary.
- Immediate actions:
  - evaluate CEL and OPA with deterministic fixtures and bounded execution controls.
- Primary sources:
  - https://cel.dev/
  - https://www.openpolicyagent.org/docs/latest/

### 9. Secure Development Framework Mapping

- Why it matters:
  - aligns project practices to recognized secure development controls for audits.
- Adoption intent:
  - map CI/release controls to SSDF practice statements.
- Immediate actions:
  - create SSDF control mapping checklist in docs once phase 2 work begins.
- Primary sources:
  - https://csrc.nist.gov/pubs/sp/800/218/final

## Cadence

- Review this matrix at least once per release cycle.
- Move completed items into architecture and workflow docs with explicit implementation notes.
- Record dropped or deferred items with rationale to avoid decision churn.
