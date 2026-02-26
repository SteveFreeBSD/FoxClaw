# Windows Share Stability Baseline

Use this baseline for reliable Linux->Windows profile soak runs.

1. Validate mount and profile visibility:
   `make windows-share-preflight`
2. Run batch with conservative SMB settings:
   `foxclaw acquire windows-share-batch --source-root /mnt/firefox-profiles --staging-root <stage> --out-root <out> --workers 1 --profile-timeout-seconds 900 --allow-active-profile --treat-high-findings-as-success`
3. Keep staging mandatory; do not scan the mount directly.
4. Treat `b67gz6f3.default` as a degenerate stub profile and exclude it from performance baselines.

Notes:
- Preflight accepts layered mount types (`autofs` + `cifs`) and requires `cifs` to be present.
- Timeout failures are operational errors and are reported per-profile in `windows-share-batch-summary.json`.
