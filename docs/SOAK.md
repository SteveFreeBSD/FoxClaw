# Soak Testing Runbook

This runbook defines long-run stability soak execution for FoxClaw with reproducible artifacts.

## Goals

- Catch flakiness and race conditions that short CI runs miss.
- Validate deterministic snapshot behavior under repeated execution.
- Validate ruleset trust fail-closed behavior under repeated execution.
- Exercise fuzz resilience and container Firefox matrix (`esr`, `beta`, `nightly`).
- Exercise native SIEM validation through the Wazuh NDJSON smoke lane when enabled.
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
- `0` Wazuh SIEM runs by default (enable with `--siem-wazuh-runs`)
- `1` Firefox matrix run (`esr`, `beta`, `nightly`)

## Launch (overnight)

Recommended reduced gate run:

```bash
scripts/soak_runner.sh \
  --duration-hours 1 \
  --max-cycles 1 \
  --stage-timeout-seconds 1800 \
  --integration-runs 1 \
  --snapshot-runs 1 \
  --synth-count 1 \
  --fuzz-count 1 \
  --adversary-runs 0 \
  --siem-wazuh-runs 1 \
  --matrix-runs 0 \
  --label ws78-gate
```

Recommended overnight soak:

```bash
read -rsp "FoxClaw soak sudo password: " SOAK_SUDO_PASSWORD
echo
export SOAK_SUDO_PASSWORD
systemd-run --user \
  --unit foxclaw-soak-overnight \
  --same-dir \
  --collect \
  scripts/soak_runner.sh \
    --duration-hours 10 \
    --stage-timeout-seconds 1800 \
    --siem-wazuh-runs 1 \
    --label overnight-phase1 \
    --output-root /var/tmp/foxclaw-soak
unset SOAK_SUDO_PASSWORD
```

Quick commands:

```bash
read -rsp "FoxClaw soak sudo password: " SOAK_SUDO_PASSWORD
echo
export SOAK_SUDO_PASSWORD
make soak-smoke
make soak-smoke-adversary
make soak-smoke-fuzz1000
make soak-daytime
make soak-daytime-fuzz1000
make soak-daytime-detached
unset SOAK_SUDO_PASSWORD
make soak-status
make soak-stop
```

Windows-share presoak preflight (recommended before long soak):

```bash
scan_exit=0
foxclaw scan \
  --profile /mnt/firefox-profiles/<profile-name> \
  --output /var/tmp/foxclaw-presoak-share/<profile-name>/foxclaw.json \
  --sarif-out /var/tmp/foxclaw-presoak-share/<profile-name>/foxclaw.sarif \
  --snapshot-out /var/tmp/foxclaw-presoak-share/<profile-name>/foxclaw.snapshot.json \
  --stage-manifest-out /var/tmp/foxclaw-presoak-share/<profile-name>/stage-manifest.json \
  --allow-active-profile || scan_exit=$?

if [ "${scan_exit}" -ne 0 ] && [ "${scan_exit}" -ne 2 ]; then
  exit "${scan_exit}"
fi
```

If your presoak wrapper must treat `HIGH` findings as success (`0`), use
`foxclaw acquire windows-share-scan --treat-high-findings-as-success`.

Current Windows-share profile lineage:
- `ejm2bj4s.foxclaw-test` was renamed to `foxclaw-seed.default`.
- `foxclaw-seed.default` was used to seed 50 sibling profiles in the current
  `/mnt/firefox-profiles` directory.

Verify these outputs exist before starting the soak harness:

- `foxclaw.json`
- `foxclaw.sarif`
- `foxclaw.snapshot.json`
- `stage-manifest.json`

Recommended (survives terminal logout):

```bash
read -rsp "FoxClaw soak sudo password: " SOAK_SUDO_PASSWORD
echo
export SOAK_SUDO_PASSWORD
systemd-run --user \
  --unit foxclaw-soak-overnight \
  --same-dir \
  --collect \
  scripts/soak_runner.sh \
    --duration-hours 10 \
    --label overnight-phase1 \
    --output-root /var/tmp/foxclaw-soak
unset SOAK_SUDO_PASSWORD
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
- The native Wazuh lane requires the pinned image `wazuh/wazuh-manager:4.14.3` to exist locally before the run:

```bash
docker image inspect wazuh/wazuh-manager:4.14.3 >/dev/null
```

- Synthetic and fuzz phases are deterministic by default (`synth-seed=424242`, `fuzz-seed=525252`).
- Default fidelity thresholds are `synth=70`, `fuzz=50`.
- Profile generation stays offline-by-default unless runner flags explicitly enable live AMO fetches.
- Generated profiles include realistic NSS, HSTS, storage, and favicon layers:
- `key4.db` / `cert9.db` / `pkcs11.txt`
- `SiteSecurityServiceState.txt`
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
- `soak-summary.json`: machine-readable rollup with stage counts, Wazuh image, NDJSON event totals, and top `rule_id` values.
- `results.tsv`: machine-readable step records:
  - `cycle`, `stage`, `iteration`, `exit_code`, `status`, `duration_sec`, timestamps, `log_path`, `artifact_path`
- `summary.txt`: run outcome and aggregate counts.
- `logs/*.log`: per-step raw logs.
- `snapshots/cycle-*/`: deterministic snapshot outputs and `sha256.txt`.
- `synth/cycle-*/fidelity-summary.json`: synth profile realism gate output.
- `fuzz/cycle-*/fidelity-summary.json`: fuzz profile realism gate output.
- `siem-wazuh/cycle-*/`: native FoxClaw -> NDJSON -> Wazuh smoke artifacts (`foxclaw.ndjson`, `wazuh-logtest.txt`, `alerts-excerpt.jsonl`, `ossec-log-tail.txt`, `manifest.json`) when `--siem-wazuh-runs` is enabled.

## Wazuh Lane

Run just the native Wazuh validation path without a full overnight soak:

```bash
.venv/bin/python scripts/siem_wazuh_smoke.py \
  --output-dir /var/tmp/foxclaw-wazuh-smoke \
  --python-bin .venv/bin/python
```

Run one reduced soak cycle with the Wazuh lane enabled:

```bash
scripts/soak_runner.sh \
  --duration-hours 1 \
  --max-cycles 1 \
  --stage-timeout-seconds 1800 \
  --integration-runs 1 \
  --snapshot-runs 1 \
  --synth-count 1 \
  --fuzz-count 1 \
  --adversary-runs 0 \
  --siem-wazuh-runs 1 \
  --matrix-runs 0 \
  --label ws75-wazuh
```

Expected outcome:

- `summary.txt` reports `overall_status=PASS`
- `soak-summary.json` exists in the run root
- `results.tsv` contains a passing `siem_wazuh` stage
- `siem-wazuh/cycle-*/run-*/manifest.json` records the pinned image, NDJSON path, `wazuh-logtest` artifact, `alerts.json` excerpt, and `ossec.log` tail path

## Post-Run Forensic Queries

Rebuild the local session-memory index before reviewing soak evidence:

```bash
python scripts/memory_index.py build
```

Expected output: `[memory-index] built artifacts/session_memory/index.sqlite ...`

Run a recall query against the local checkpoint journal:

```bash
python scripts/memory_query.py "\"WS-78\"" --limit 5
```

Expected terminal output:

- `[memory-query] top <n> hits for: "WS-78"` followed by checkpoint rows
- or `[memory-query] no hits for: "WS-78"`
- or, when the FTS table was damaged but the base index still exists, `[memory-query] warning: checkpoints_fts unavailable; using LIKE fallback`

Expected `soak-summary.json` forensic shape:

```json
{
  "memory_index_status": "ok",
  "memory_index_path": "/abs/path/to/session-memory/index.sqlite",
  "last_checkpoint_id": 31
}
```

If no local memory index exists, the summary still succeeds with:

```json
{
  "memory_index_status": "fail",
  "memory_index_path": "/abs/path/to/session-memory/index.sqlite"
}
```

`soak-summary.json` also records `memory_index_status`, `memory_index_path`, and `last_checkpoint_id` when the local recall index is available.

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

## Troubleshooting

Inspect these files first, in this order:

1. `<run-id>/soak-summary.json`
2. `<run-id>/summary.txt`
3. `<run-id>/results.tsv`
4. `<run-id>/logs/cycle-*-siem-wazuh-*.log`
5. `<run-id>/siem-wazuh/cycle-*/run-*/foxclaw-scan.log`
6. `<run-id>/siem-wazuh/cycle-*/run-*/wazuh-logtest.txt`
7. `<run-id>/siem-wazuh/cycle-*/run-*/alerts-excerpt.jsonl`
8. `<run-id>/siem-wazuh/cycle-*/run-*/ossec-log-tail.txt`
9. `<run-id>/siem-wazuh/cycle-*/run-*/manifest.json`

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
