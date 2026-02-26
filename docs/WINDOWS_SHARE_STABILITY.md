# Windows Share Stability Baseline

Use this baseline for reliable Linux→Windows profile soak runs.

1. Validate mount and profile visibility:
   `make windows-share-preflight`
2. Run batch with conservative SMB settings:
   `foxclaw acquire windows-share-batch --source-root /mnt/firefox-profiles --staging-root <stage> --out-root <out> --workers 1 --profile-timeout-seconds 900 --allow-active-profile --treat-high-findings-as-success`
3. Keep staging mandatory; do not scan the mount directly.
4. Treat `b67gz6f3.default` as a degenerate stub profile and exclude it from performance baselines.

## Profile generator scripts

Recreate or refresh the `/mnt/firefox-profiles` fixtures on Windows by following the guide in `scripts/windows_auth_gen/README.md`. Key scripts:

- `scripts/windows_auth_gen/generate_profiles.ps1`: clones `foxclaw-seed.default`, runs the PowerShell generator, and emits mutation metadata overlays.
- `scripts/windows_auth_gen/mutate_profile.mjs`: drives Playwright to recreate realistic user activity, writes the `foxclaw-sim-metadata.json` manifest, and exposes the `expected_scan_signals` bundle used during validation.

Use the generator output with `foxclaw scan` (include `--stage-manifest-out`) to ensure `foxclaw.json.credentials` matches the generator’s `expected_scan_signals.credentials`. Treat any drift in `saved_logins_count`, `vulnerable_passwords_count`, `dismissed_breach_alerts_count`, or `insecure_http_login_count` as a signal to rerun the generator and update your soak pool.

Notes:
- Preflight accepts layered mount types (`autofs` + `cifs`) and requires `cifs` to be present.
- Timeout failures are operational errors and are reported per-profile in `windows-share-batch-summary.json`.
