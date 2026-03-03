# Windows Share Stability Baseline

Use this baseline for reliable Linux->Windows profile soak runs.

1. Preferred: launch the combined workflow with the first-class wrapper:
   `python scripts/windows_share_comprehensive_soak.py --source-root /mnt/firefox-profiles --lock-policy allow-active --siem-wazuh-runs 1 --siem-elastic-fleet-runs 1 --label windows-share-comprehensive`
2. The wrapper will:
   - validate the mount with `scripts/windows_share_preflight.sh`
   - prove direct staged scanning against one mounted profile
   - run a bounded `foxclaw acquire windows-share-batch` sanity pass with explicit include policy
   - optionally run the Wazuh and Elastic Fleet SIEM smoke lanes inside the detached soak
   - launch the detached long soak and record the unit/run-dir trail in one manifest
3. Keep staging mandatory; do not scan the mount directly except for the wrapper’s staged presoak proof.
4. Treat `b67gz6f3.default` as a degenerate stub profile and exclude it from performance baselines.

Manual fallback:

1. `make windows-share-preflight`
2. `foxclaw acquire windows-share-batch --source-root /mnt/firefox-profiles --staging-root <stage> --out-root <out> --workers 1 --profile-timeout-seconds 900 --allow-active-profile --treat-high-findings-as-success`

## Profile generator scripts

Recreate or refresh the `/mnt/firefox-profiles` fixtures on Windows by following the guide in `scripts/windows_auth_gen/README.md`. Key scripts:

- `scripts/windows_auth_gen/generate_profiles.ps1`: clones `foxclaw-seed.default`, runs the PowerShell generator, and emits mutation metadata overlays.
- `scripts/windows_auth_gen/mutate_profile.mjs`: performs deterministic profile mutation via Node.js + `better-sqlite3`, writes the `foxclaw-sim-metadata.json` manifest, and exposes the `expected_scan_signals` bundle used during validation.

Use the generator output with `foxclaw scan` (include `--stage-manifest-out`) to ensure `foxclaw.json.credentials` matches the generator’s `expected_scan_signals.credentials`. Treat any drift in `saved_logins_count`, `vulnerable_passwords_count`, `dismissed_breach_alerts_count`, or `insecure_http_login_count` as a signal to rerun the generator and update your soak pool.

Notes:
- Preflight accepts layered mount types (for example `autofs` stacked on an SMB mount) and requires that at least one supported SMB filesystem type is present: `cifs`, `smb3`, `smbfs`, or `fuse.smbnetfs`.
- Timeout failures are operational errors and are reported per-profile in `windows-share-batch-summary.json`.
- The comprehensive wrapper keeps mixed corpora explicit via `--corpus-mode mixed|generated-only` and records seed/stub classification in its workflow manifest.
- The Elastic Fleet smoke runner uses the existing `foxclaw-agent` lab container by default and rotates the tailed ECS filename per run so repeated soak cycles do not stick on filestream registry state.
