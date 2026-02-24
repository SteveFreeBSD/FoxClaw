# Soak Testing Runbook

This runbook defines long-run stability soak execution for FoxClaw with reproducible artifacts.

## Goals

- Catch flakiness and race conditions that short CI runs miss.
- Validate deterministic snapshot behavior under repeated execution.
- Validate ruleset trust fail-closed behavior under repeated execution.
- Exercise fuzz resilience and container Firefox matrix (`esr`, `beta`, `nightly`).
- Produce structured logs for post-run forensic analysis.

## Harness

- Script: `scripts/soak_runner.sh`
- Default duration: `10` hours
- Default cycle workload:
- `5` integration runs
- `5` snapshot determinism runs + hash consistency check
- `1` trust-manifest smoke stage (scan/fleet positive + fail-closed negatives)
- `1` synth run (`50` realistic profiles; fidelity-gated)
- `1` fuzz run (`500` realistic+mutated profiles; fidelity-gated)
- `0` adversary runs by default (enable with `--adversary-runs`)
- `1` Firefox matrix run (`esr`, `beta`, `nightly`)

## Launch (overnight)

Quick commands:

```bash
make soak-smoke SOAK_SUDO_PASSWORD='<sudo-password>'
make soak-smoke-adversary SOAK_SUDO_PASSWORD='<sudo-password>'
make soak-smoke-fuzz1000 SOAK_SUDO_PASSWORD='<sudo-password>'
make soak-daytime SOAK_SUDO_PASSWORD='<sudo-password>'
make soak-daytime-fuzz1000 SOAK_SUDO_PASSWORD='<sudo-password>'
make soak-daytime-detached SOAK_SUDO_PASSWORD='<sudo-password>'
make soak-status
make soak-stop
```

Windows-share presoak preflight (recommended before long soak):

```bash
foxclaw acquire windows-share-scan \
  --source-profile /mnt/firefox-profiles/<profile-name> \
  --output-dir /var/tmp/foxclaw-presoak-share/<profile-name> \
  --allow-active-profile \
  --treat-high-findings-as-success
```

Verify these outputs exist before starting the soak harness:

- `foxclaw.json`
- `foxclaw.sarif`
- `foxclaw.snapshot.json`
- `stage-manifest.json`

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
- Synthetic and fuzz phases are deterministic by default (`synth-seed=424242`, `fuzz-seed=525252`).
- Default fidelity thresholds are `synth=70`, `fuzz=50`.
- Profile generation stays offline-by-default unless runner flags explicitly enable live AMO fetches.
- Generated profiles include realistic NSS, HSTS, storage, and favicon layers:
- `key4.db` / `cert9.db` / `pkcs11.txt`
- `SiteSecurityServiceState.bin`
- `storage/default/`
- `favicons.sqlite`

## High-Memory Fuzz Mode (1000 Profiles)

For systems with larger memory budgets (for example 64 GB RAM), you can run
heavier fuzz cycles:

```bash
make soak-daytime-fuzz1000 SOAK_SUDO_PASSWORD='<sudo-password>'
```

Or run custom overnight parameters directly:

```bash
SOAK_SUDO_PASSWORD='<sudo-password>' \
scripts/soak_runner.sh \
  --duration-hours 10 \
  --integration-runs 5 \
  --snapshot-runs 5 \
  --fuzz-count 1000 \
  --matrix-runs 1 \
  --label overnight-fuzz1000
```

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
- `synth/cycle-*/fidelity-summary.json`: synth profile realism gate output.
- `fuzz/cycle-*/fidelity-summary.json`: fuzz profile realism gate output.

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
- synth/fuzz fidelity summaries report `below_min_count=0`

## Failure Triage

1. Start at `summary.txt` and `run.log`.
2. Query failed rows in `results.tsv`.
3. Open referenced `logs/*.log` for root cause.
4. For determinism drift, inspect `snapshots/cycle-*/sha256.txt`.
5. Record regression details before code changes:
   - failing stage
   - first observed cycle/iteration
   - command log path

## Post-Run Learning Extraction

Use every deep soak as a planning input, even when all steps pass.

Recommended extraction checklist:

1. Runtime concentration by stage:

```bash
awk -F'\t' 'NR>1{count[$2]++; dur[$2]+=$6} END{for (s in count) printf "%s\tcount=%d\tduration=%ds\n", s, count[s], dur[s]}' \
  /var/tmp/foxclaw-soak/<run-id>/results.tsv | sort
```

2. Determinism confirmation:

```bash
for c in /var/tmp/foxclaw-soak/<run-id>/snapshots/cycle-*; do
  echo "$(basename "$c") unique_hashes=$(awk '{print $1}' "$c/sha256.txt" | sort -u | wc -l)"
done
```

3. Fuzz/synth fidelity pressure points:

- review `fuzz/cycle-*/fidelity-summary.json`
- review `synth/cycle-*/fidelity-summary.json`
- inspect top recurring issue strings in `logs/cycle-*-fuzz.log`

4. Adversary scenario signal stability:

- review `adversary/cycle-*/adversary-summary.json`
- compare `findings_high_count` by scenario across cycles

For the latest 8h baseline and decisions, see:

- `docs/SOAK_REVIEW_2026-02-24_ULTIMATE_8H.md`
