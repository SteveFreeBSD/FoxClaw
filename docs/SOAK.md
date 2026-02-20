# Soak Testing Runbook

This runbook defines long-run stability soak execution for FoxClaw with reproducible artifacts.

## Goals

- Catch flakiness and race conditions that short CI runs miss.
- Validate deterministic snapshot behavior under repeated execution.
- Exercise fuzz resilience and container Firefox matrix (`esr`, `beta`, `nightly`).
- Produce structured logs for post-run forensic analysis.

## Harness

- Script: `scripts/soak_runner.sh`
- Default duration: `10` hours
- Default cycle workload:
  - `5` integration runs
  - `5` snapshot determinism runs + hash consistency check
  - `1` fuzz run (`500` random profiles)
  - `1` Firefox matrix run (`esr`, `beta`, `nightly`)

## Launch (overnight)

Recommended (survives terminal logout):

```bash
systemd-run --user \
  --unit foxclaw-soak-overnight \
  --same-dir \
  --collect \
  --setenv=SOAK_SUDO_PASSWORD='<sudo-password>' \
  scripts/soak_runner.sh \
    --duration-hours 10 \
    --label overnight-phase1 \
    --output-root /var/tmp/foxclaw-soak
```

Stop early if needed:

```bash
systemctl --user stop foxclaw-soak-overnight.service
```

Fallback (manual shell session):

```bash
SOAK_SUDO_PASSWORD='<sudo-password>' \
nohup scripts/soak_runner.sh \
  --duration-hours 10 \
  --label overnight-phase1 \
  --output-root /var/tmp/foxclaw-soak \
  > /var/tmp/foxclaw-soak-launch.log 2>&1 &
```

Notes:

- `SOAK_SUDO_PASSWORD` is only needed when the current user cannot access Docker socket directly.
- The password is not written to soak artifacts by the harness.

## Artifacts

Each run writes to a unique directory:

`/var/tmp/foxclaw-soak/<UTC timestamp>[-label]/`

Key files:

- `manifest.txt`: branch/commit/config/host metadata.
- `run.log`: human-readable execution timeline.
- `results.tsv`: machine-readable step records:
  - `cycle`, `stage`, `iteration`, `exit_code`, `status`, `duration_sec`, timestamps, `log_path`
- `summary.txt`: run outcome and aggregate counts.
- `logs/*.log`: per-step raw logs.
- `snapshots/cycle-*/`: deterministic snapshot outputs and `sha256.txt`.

## Monitoring

Find newest soak run:

```bash
ls -1dt /var/tmp/foxclaw-soak/* | head -n 1
```

Tail high-level status:

```bash
tail -f /var/tmp/foxclaw-soak/<run-id>/run.log
```

Watch failing steps:

```bash
awk -F'\t' 'NR==1 || $5 == "FAIL"' /var/tmp/foxclaw-soak/<run-id>/results.tsv
```

## Completion Gates

A run is considered stable when:

- `summary.txt` reports `overall_status=PASS`
- `steps_failed=0`
- snapshot hash check steps report a single unique hash per cycle
- no fuzz crash records are present in corresponding fuzz logs

## Failure Triage

1. Start at `summary.txt` and `run.log`.
2. Query failed rows in `results.tsv`.
3. Open referenced `logs/*.log` for root cause.
4. For determinism drift, inspect `snapshots/cycle-*/sha256.txt`.
5. Record regression details before code changes:
   - failing stage
   - first observed cycle/iteration
   - command log path
