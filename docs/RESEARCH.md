# Research Matrix

This matrix tracks high-value components for evolving FoxClaw into a feature-rich security application while preserving deterministic, offline-by-default scan behavior.

## Research Method

- Prefer primary specifications, official vendor docs, and maintainer-owned repositories.
- Extract implementation constraints, not just concepts (schema, limits, update cadence, permission boundaries).
- Keep network-dependent capabilities in explicit non-scan phases.

## Priority Components

### 1. Mozilla CVE Intelligence Pipeline

- Why it matters:
  - FoxClaw needs authoritative Firefox vulnerability context, not only local posture rules.
- Adoption intent:
  - ingest Mozilla advisory data into a local intelligence snapshot used by scan correlation.
- Immediate actions:
  - define canonical Mozilla advisory ingestion path and schema.
  - normalize advisory records to CVE + affected/fixed version ranges.
- Primary sources:
  - https://github.com/mozilla/foundation-security-advisories
  - https://www.mozilla.org/security/known-vulnerabilities/
  - https://www.mozilla.org/security/known-vulnerabilities/firefox/

### 2. CVE Enrichment and Version Correlation

- Why it matters:
  - Mozilla advisories alone are not sufficient for CVSS-centric prioritization.
- Adoption intent:
  - enrich Mozilla-linked CVEs with NVD/CVE data in sync phase.
- Immediate actions:
  - map Firefox product/version to NVD query model.
  - define precedence policy when NVD and Mozilla records differ.
- Primary sources:
  - https://nvd.nist.gov/developers/vulnerabilities
  - https://nvd.nist.gov/vuln/data-feeds
  - https://github.com/CVEProject/cvelistV5

### 3. Known-Exploited Prioritization Signals

- Why it matters:
  - exploitability context sharply improves triage quality.
- Adoption intent:
  - incorporate KEV and optional EPSS scoring as correlated metadata.
- Immediate actions:
  - add KEV join logic by CVE id.
  - define deterministic scoring merge order.
- Primary sources:
  - https://github.com/cisagov/kev-data
  - https://www.first.org/epss/api

### 4. Extension Inventory and Local Risk Signals

- Why it matters:
  - extension attack surface can exceed core browser configuration risk.
- Adoption intent:
  - add deterministic extension inventory and manifest-based risk checks.
- Immediate actions:
  - parse extension metadata and manifest permission fields from profile artifacts.
  - classify risky permission patterns and privileged host access.
- Primary sources:
  - https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/permissions
  - https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings

### 5. Extension Reputation and Blocklist Intelligence

- Why it matters:
  - local permissions alone miss known-malicious or blocked extensions.
- Adoption intent:
  - correlate installed extension IDs/versions against AMO API + blocklist data snapshots.
- Immediate actions:
  - define GUID normalization strategy for installed extensions.
  - ingest blocklist records into local intelligence store.
- Primary sources:
  - https://addons-server.readthedocs.io/en/latest/topics/api/addons.html
  - https://mozilla.github.io/addons-server/topics/blocklist.html

### 6. Intelligence Snapshot Store Design

- Why it matters:
  - deterministic offline correlation requires pinned intelligence snapshots.
- Adoption intent:
  - implement local snapshot-backed intelligence database with source checksums.
- Immediate actions:
  - define snapshot schema version and source manifest format.
  - include source timestamps and hashes in every sync result.
- Primary sources:
  - https://www.sqlite.org/docs.html
  - https://slsa.dev/spec/v1.2/

### 7. SARIF Quality and Ingestion Reliability

- Why it matters:
  - correlated findings still need robust code-scanning ingestion.
- Adoption intent:
  - preserve schema-clean SARIF with stable fingerprints and controlled result volume.
- Immediate actions:
  - enforce SARIF budgets and stable categories for multi-run uploads.
  - keep schema validation tests mandatory.
- Primary sources:
  - https://www.oasis-open.org/standard/sarifv2-1-os/
  - https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
  - https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github
  - https://docs.github.com/en/code-security/reference/code-scanning/sarif-support-for-code-scanning

### 8. Build Provenance and Artifact Attestation

- Why it matters:
  - consumers need verifiable trust in build and release lineage.
- Adoption intent:
  - emit attestations and provenance for release artifacts.
- Immediate actions:
  - add attestation workflow stage and verification docs.
- Primary sources:
  - https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds
  - https://github.com/actions/attest-build-provenance
  - https://github.com/in-toto/attestation

### 9. Packaging and Dependency Hardening

- Why it matters:
  - secure delivery and dependency hygiene are part of audit readiness.
- Adoption intent:
  - enforce dependency review and trusted publishing controls.
- Immediate actions:
  - gate PR dependency changes.
  - add scheduled vulnerability scans for Python dependencies.
- Primary sources:
  - https://docs.pypi.org/trusted-publishers/using-a-publisher/
  - https://packaging.python.org/en/latest/guides/writing-pyproject-toml/
  - https://github.com/actions/dependency-review-action
  - https://github.com/pypa/pip-audit
  - https://osv.dev/docs/

### 10. SBOM and Compliance Mapping

- Why it matters:
  - enterprise adoption requires transparent component inventories and control alignment.
- Adoption intent:
  - produce release SBOM artifacts and map controls to SSDF.
- Immediate actions:
  - choose SPDX or CycloneDX export baseline.
  - begin SSDF mapping once vulnerability-intel phase starts implementation.
- Primary sources:
  - https://spdx.dev/specifications/
  - https://cyclonedx.org/specification/overview/
  - https://csrc.nist.gov/pubs/sp/800/218/final

## Cadence

- Revisit this matrix each release cycle.
- Promote completed items into architecture/workflow docs with implementation notes.
- Record deferred/dropped items with explicit rationale.

## Research Document Index

This file (`RESEARCH.md`) is the **master research matrix**. Dated research documents below capture deep dives into specific topics at a point in time:

| Document | Focus | Date |
|---|---|---|
| `RESEARCH_2026-02-20.md` | Ecosystem alignment (Arkenfox, AMO, KEV/NVD feeds, osquery/Fleet) | 2026-02-20 |
| `RESEARCH_2026-02-22_RUST_APPLIANCE.md` | Rust appliance transition (build hygiene, contracts, signed distribution) | 2026-02-22 |
| `RESEARCH_2026-02-22_WINDOWS_SHARE_AUDIT.md` | Enterprise Windows-share audit (SMB staging, lock handling) | 2026-02-22 |
| `RESEARCH_2026-02-24_ADVERSARY_TESTBED.md` | Adversary scenario profiles and soak integration | 2026-02-24 |
| `RESEARCH_2026-02-24_THREAT_SURFACE_EXPANSION.md` | Threat surface gap analysis, CVE landscape, ATT&CK mappings, self-learning | 2026-02-24 |

## Related Documents (Not Research)

These docs implement or operationalize research findings — they are not research themselves:

- `VULNERABILITY_INTEL.md`: **implementation strategy** for the intelligence pipeline (sync, correlation, storage schema). Implements research items 1–6 from this matrix.
- `ROADMAP.md`: **execution plan** that sequences research into phased delivery.
- `WORKSLICES.md`: **ordered task queue** with dependencies and acceptance criteria.

