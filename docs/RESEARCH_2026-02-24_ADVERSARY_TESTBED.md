# Research: Adversary Testbed Expansion (2026-02-24)

## Objective

Expand FoxClaw profile-generation and soak coverage for high-risk Firefox threat classes:

- malicious extension behavior and sideload abuse,
- policy/prefs hardening bypass and risky config drift,
- credential exposure artifacts (logins/forms/history crossover),
- injected storage/state artifacts used by adware or infostealer playbooks.

## External Baselines

- Mozilla Security Advisories: https://www.mozilla.org/en-US/security/advisories/
- Firefox Enterprise Policy Surface: https://mozilla.github.io/policy-templates/
- Firefox Add-on Policy / abuse controls: https://extensionworkshop.com/documentation/publish/add-on-policies/
- Firefox password manager operational model: https://support.mozilla.org/en-US/kb/password-manager-remember-delete-edit-logins
- MITRE ATT&CK browser-extension persistence (T1176): https://attack.mitre.org/techniques/T1176/
- OpenWPM automation model (benchmark for repeatable browser telemetry): https://github.com/openwpm/OpenWPM

## FoxClaw Testbed Direction

1. Keep synthetic adversary profiles deterministic and offline-by-default.
2. Model threat classes as explicit scenarios (not random one-off mutations).
3. Require every generated adversary profile to round-trip through `foxclaw scan`.
4. Treat scan exit `2` as expected signal; fail only on operational errors.
5. Track per-profile provenance (`scenario`, `seed`, `mutation`, `exit_code`) in machine-readable summaries.

## Implemented in this slice

- Added `scripts/adversary_profiles.py` to generate scenario-driven adversary profiles and immediately scan them.
- Added `make adversary-smoke` for quick local threat-lane validation.
- Added soak integration knobs:
  - `--adversary-runs`
  - `--adversary-count`

This keeps adversary coverage integrated with existing soak harness without weakening deterministic gates.
