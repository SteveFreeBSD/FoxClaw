# Research Notes

Date: 2026-02-19
Goal: identify proven patterns for Firefox posture auditing, deterministic local scanning, and safe remediation controls.

## Sources (competitors + official docs)
1. Mozilla Support: Firefox profiles data location
   - https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data
   - Borrow: canonical profile file/directory expectations and artifact names (`prefs.js`, `extensions.json`, SQLite files).
2. Mozilla Support: Dedicated profiles per installation
   - https://support.mozilla.org/en-US/kb/dedicated-profiles-firefox-installation
   - Borrow: profile-per-install behavior; motivates explicit profile selection rationale.
3. Mozilla policy templates documentation
   - https://mozilla.github.io/policy-templates/
   - Borrow: policy key naming and machine policy structure for posture checks.
4. Mozilla policy templates repository
   - https://github.com/mozilla/policy-templates
   - Borrow: policy examples and compatibility expectations.
5. Firefox source docs: Enterprise policies
   - https://firefox-source-docs.mozilla.org/browser/components/enterprisepolicies/docs/index.html
   - Borrow: source-of-truth policy behavior by channel/platform.
6. SQLite PRAGMA quick_check
   - https://www.sqlite.org/pragma.html#pragma_quick_check
   - Borrow: non-invasive integrity checking semantics.
7. SQLite URI filenames
   - https://www.sqlite.org/uri.html
   - Borrow: read-only `mode=ro` access pattern.
8. OASIS SARIF 2.1.0 specification
   - https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
   - Borrow: required top-level schema fields and result object conventions.
9. SARIF technical committee repository
   - https://github.com/oasis-tcs/sarif-spec
   - Borrow: practical examples and schema alignment checks.
10. osquery configuration and packs
    - https://osquery.readthedocs.io/en/stable/deployment/configuration/
    - Borrow: declarative checks, stable output for automation, host-local collection model.
11. Lynis project
    - https://github.com/CISOfy/lynis
    - Borrow: audit-first posture checks and remediation guidance separated from evidence.
12. ComplianceAsCode content (SCAP Security Guide)
    - https://github.com/ComplianceAsCode/content
    - Borrow: data-driven policy/rule organization and baseline layering.
13. OpenSCAP user manual
    - https://static.open-scap.org/openscap-1.4/oscap_user_manual.html
    - Borrow: strict separation of evaluation and remediation workflows.
14. Wazuh security configuration assessment
    - https://wazuh.com/blog/security-configuration-assessment/
    - Borrow: policy-to-check mapping and drift-oriented reporting language.
15. Trivy reporting docs
    - https://trivy.dev/latest/docs/configuration/reporting/
    - Borrow: multi-format output model (human + machine).
16. arkenfox user.js project
    - https://github.com/arkenfox/user.js
    - Borrow: curated Firefox preference hardening concepts and profile-safe preference semantics.

## Patterns To Adopt

### Rulesets
- Keep rules declarative in YAML with explicit metadata (id, title, severity, rationale/remediation).
- Keep DSL intentionally small at first; add checks only when evidence reliability is high.
- Version rulesets and gate by Firefox major range to avoid false positives from version drift.

### Profile Discovery
- Discover from Linux-standard locations first (`XDG_CONFIG_HOME`, then `~/.config`, then `~/.mozilla`).
- Parse `profiles.ini` and keep deterministic tie-breaks.
- Prefer an actively locked profile when present; otherwise score by explicit signals (`.default-release`, `Default=1`, profile activity proxies).
- Always emit selected-profile reason metadata for auditability.

### Artifact Parsing
- Parse local files directly (`prefs.js`, `user.js`, `extensions.json`, `policies.json`) with graceful fallback for missing/corrupt files.
- Treat evidence as immutable inputs; never mutate files in collection code.
- For SQLite health checks, use read-only URI mode and run integrity-oriented PRAGMAs only.

### Outputs (SARIF + JSON + text)
- Maintain a stable internal finding schema, then map to Rich/JSON/SARIF renderers.
- SARIF: ensure required fields (`version`, `$schema`, `runs`, `tool`, `results`) and stable `ruleId` values.
- Keep deterministic ordering in outputs for diffability.

### Enforcement Safeguards
- Default to audit-only actions.
- Require explicit phase transition from `plan` to `apply`.
- Require confirmation before any mutation unless operator passes an explicit non-interactive override.
- Keep remediation implementation in separate modules from collectors.

## Explicitly Rejected Patterns
- Runtime network lookups during scans (privacy and determinism risk).
- Opaque, heuristic-only risk scoring with no reason strings.
- Mixing evidence collection and file mutation in a single command path.
