# Windows Profile Generator Notes

This folder builds synthetic Firefox profiles on Windows for SMB/share scanning.

## Scripts

- `generate_profiles.ps1`: clones a seed profile and runs mutation per profile.
- `mutate_profile.mjs`: performs deterministic profile mutation via Node.js + `better-sqlite3` and writes simulation metadata.

## Seed Lineage

- prior seed name: `ejm2bj4s.foxclaw-test`
- current seed name: `foxclaw-seed.default`
- the current profile-generation run seeded 50 sibling profiles from
  `foxclaw-seed.default` under the active Firefox profile directory.

## Parameters

- `-Count <int>`: Total profiles to generate.
- `-Workers <int>`: (Optional) PowerShell 7+ only. Launch `N` concurrent mutator jobs during the mutation phase. Defaults to `(CPU cores / 2)`, capped at 10.
- `-Overwrite`: (Optional) Force delete existing destination profiles before cloning.
- `-Resume`: (Optional) Skip generating profiles that already have a successful `status: "ok"` manifest.
- `-StartIndex` / `-EndIndex`: (Optional) Bounds for resuming or chunking generation work.

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

Use `foxclaw scan` on generated profiles (mounted share path) and compare
`foxclaw.json.credentials` against `expected_scan_signals.credentials`. Include
`--stage-manifest-out` so each validation run preserves staging provenance.
Treat material mismatch as generator drift and fix scripts before long soak runs.
