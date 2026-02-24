# Windows Profile Generator Notes

This folder builds synthetic Firefox profiles on Windows for SMB/share scanning.

## Scripts

- `generate_profiles.ps1`: clones a seed profile and runs mutation per profile.
- `mutate_profile.mjs`: drives Playwright activity and writes simulation metadata.

## Scan-Driven Signals

`mutate_profile.mjs` writes:

- `<profile>/foxclaw-sim-metadata.json`
- `<profile>/logins.json` (scenario/probability-based credential seeding)

`foxclaw-sim-metadata.json.expected_scan_signals.credentials` is the intended
FoxClaw credential evidence baseline:

- `saved_logins_count`
- `vulnerable_passwords_count`
- `dismissed_breach_alerts_count`
- `insecure_http_login_count`

Use `foxclaw acquire windows-share-scan` on generated profiles and compare
`foxclaw.json.credentials` against `expected_scan_signals.credentials`. Treat
material mismatch as generator drift and fix scripts before long soak runs.
