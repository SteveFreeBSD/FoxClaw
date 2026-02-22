# Windows Share Firefox Testing Runbook

This runbook standardizes FoxClaw testing against Firefox profiles stored on Windows file shares.

## Why this lane exists

Enterprise teams often centralize endpoint artifacts on SMB shares for remote triage. Firefox profile databases are SQLite-backed, and SQLite documents network-locking and live-copy corruption risks. FoxClaw therefore uses a **stage-local-then-scan** workflow:

- copy profile from share to local snapshot,
- keep staged copy read-only,
- run deterministic scan on local snapshot,
- retain a provenance manifest with scan artifacts.

## Security baseline (required)

1. Use SMB signing and encryption baselines consistent with current Windows 11 24H2 / Server 2025 guidance.
2. Use least-privilege read-only access for collection principals.
3. Avoid scanning profiles in place on a live share path.

## Profile source paths to collect

Standard Firefox install path:

- `%APPDATA%\Mozilla\Firefox\Profiles\<profile-id>`

MSIX path variant:

- `%LOCALAPPDATA%\Packages\Mozilla.Firefox\LocalCache\Roaming\Mozilla\Firefox\Profiles\<profile-id>`

## Acquisition options

### Option A: Windows host collector (recommended)

Copy from UNC to local collector storage first, then run FoxClaw staging script.

Example `robocopy` command (tune destination/share names for your environment):

```powershell
robocopy "\\fileserver\forensics\FirefoxProfiles\jdoe.default-release" "C:\collect\jdoe.default-release" /E /ZB /COPY:DAT /DCOPY:DAT /R:1 /W:1 /XJ
```

Notes:

- `/ZB` supports restartable copy and backup-mode fallback when authorized.
- Keep retries bounded (`/R:1 /W:1`) to avoid long hangs in automation.
- Use `robocopy` only for acquisition; FoxClaw scan remains local/offline.

### Option B: Linux collector with mounted SMB share

Mount the share read-only in the collector OS, then use the FoxClaw staging script against the mount path.

## FoxClaw staged share scan

Use `scripts/windows_share_scan.py` for deterministic staging + scan artifact generation:

```bash
python scripts/windows_share_scan.py \
  --source-profile /mnt/forensics/FirefoxProfiles/jdoe.default-release \
  --ruleset foxclaw/rulesets/strict.yml \
  --output-dir /var/tmp/foxclaw-share-jdoe \
  --snapshot-id jdoe-20260222T190000Z
```

Behavior:

- fails closed by default if lock markers (`parent.lock`, `.parentlock`, `lock`) are present,
- copies profile into `<staging-root>/<snapshot-id>/profile`,
- removes write bits from staged files unless `--keep-stage-writeable` is set,
- runs deterministic FoxClaw JSON/SARIF/snapshot outputs,
- writes staging manifest (`stage-manifest.json`) with source path, copy stats, and scan command/exit code.

If acquisition used a crash-consistent snapshot (for example VSS) and lock markers are expected, allow override:

```bash
python scripts/windows_share_scan.py \
  --source-profile "\\\\fileserver\\forensics\\FirefoxProfiles\\jdoe.default-release" \
  --allow-active-profile
```

## Mini soak for this lane

Run a quick validation loop for share-lane integrations:

```bash
scripts/soak_runner.sh \
  --duration-hours 1 \
  --max-cycles 1 \
  --integration-runs 1 \
  --snapshot-runs 1 \
  --synth-count 4 \
  --fuzz-count 4 \
  --matrix-runs 0 \
  --label mini-windows-share-lane
```

## Operational guardrails

- Never point production scans directly at mutable SMB profile paths.
- Preserve staging manifests alongside scan outputs for audit and incident reconstruction.
- Keep this lane out of default runtime scan paths to maintain FoxClaw offline-by-default guarantees.

## References

- `docs/RESEARCH_2026-02-22_WINDOWS_SHARE_AUDIT.md`
- `docs/SECURITY_MODEL.md`
- `docs/TESTBED.md`
