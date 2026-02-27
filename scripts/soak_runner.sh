#!/usr/bin/env bash
# --------------------------------------------------------------------------
# soak_runner.sh — Long-run stability harness for FoxClaw.
#
# Runs repeated integration, trust-manifest scan checks, snapshot determinism,
# fuzz, and Firefox container matrix checks with structured logs for post-run
# analysis.
# --------------------------------------------------------------------------
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/soak_runner.sh [options]

Options:
  --duration-hours <N>     Total soak duration in hours (default: 10).
  --output-root <path>     Root directory for soak artifacts (default: /var/tmp/foxclaw-soak).
  --label <text>           Optional run label appended to run directory.
  --integration-runs <N>   Integration iterations per cycle (default: 5).
  --snapshot-runs <N>      Snapshot scans per cycle for determinism check (default: 5).
  --synth-count <N>        Realistic synthetic profiles per cycle (default: 50).
  --synth-seed <N>         Deterministic synth generator seed (default: 424242).
  --synth-mode <name>      Synth mode: realistic|bootstrap (default: realistic).
  --synth-mutation-budget <N> Mutations per synth profile (default: 0).
  --synth-fidelity-min-score <N> Min realism score for synth profiles (default: 70).
  --require-launch-gate    Run Firefox launch gate for synth/fuzz profile batches.
  --launch-gate-min-score <N> Min realism score after Firefox launch gate (default: 50).
  --fuzz-count <N>         Profiles per fuzz cycle (default: 500).
  --fuzz-seed <N>          Deterministic fuzz generator seed (default: 525252).
  --fuzz-mode <name>       Fuzz mode: realistic|chaos (default: chaos).
  --fuzz-mutation-budget <N> Base mutations per fuzz profile (default: 3).
  --fuzz-fidelity-min-score <N> Min realism score for fuzz profiles (default: 50).
  --adversary-runs <N>      Adversary testbed runs per cycle (default: 0).
  --adversary-count <N>     Profiles per adversary scenario per run (default: 1).
  --siem-wazuh-runs <N>     Wazuh NDJSON smoke runs per cycle (default: 0).
  --matrix-runs <N>        Firefox matrix iterations per cycle (default: 1).
  --max-cycles <N>         Optional hard cap on cycle count (default: 0 = unlimited until deadline).
  -h, --help               Show this help.

Environment:
  SOAK_SUDO_PASSWORD       Optional sudo password for docker when current user lacks docker socket access.

Artifacts:
  <output-root>/<timestamp>[-label]/
    manifest.txt
    run.log
    results.tsv
    summary.txt
    logs/*.log
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"

DURATION_HOURS=10
OUTPUT_ROOT="/var/tmp/foxclaw-soak"
LABEL=""
INTEGRATION_RUNS=5
SNAPSHOT_RUNS=5
SYNTH_COUNT=50
SYNTH_SEED=424242
SYNTH_MODE="realistic"
SYNTH_MUTATION_BUDGET=0
SYNTH_FIDELITY_MIN_SCORE=70
FUZZ_COUNT=500
FUZZ_SEED=525252
FUZZ_MODE="chaos"
FUZZ_MUTATION_BUDGET=3
FUZZ_FIDELITY_MIN_SCORE=50
ADVERSARY_RUNS=0
ADVERSARY_COUNT=1
SIEM_WAZUH_RUNS=0
REQUIRE_LAUNCH_GATE=0
LAUNCH_GATE_MIN_SCORE=50
MATRIX_RUNS=1
MAX_CYCLES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration-hours)   DURATION_HOURS="${2:-}"; shift 2 ;;
    --output-root)      OUTPUT_ROOT="${2:-}"; shift 2 ;;
    --label)            LABEL="${2:-}"; shift 2 ;;
    --integration-runs) INTEGRATION_RUNS="${2:-}"; shift 2 ;;
    --snapshot-runs)    SNAPSHOT_RUNS="${2:-}"; shift 2 ;;
    --synth-count)      SYNTH_COUNT="${2:-}"; shift 2 ;;
    --synth-seed)       SYNTH_SEED="${2:-}"; shift 2 ;;
    --synth-mode)       SYNTH_MODE="${2:-}"; shift 2 ;;
    --synth-mutation-budget) SYNTH_MUTATION_BUDGET="${2:-}"; shift 2 ;;
    --synth-fidelity-min-score) SYNTH_FIDELITY_MIN_SCORE="${2:-}"; shift 2 ;;
    --require-launch-gate)      REQUIRE_LAUNCH_GATE=1; shift 1 ;;
    --launch-gate-min-score)    LAUNCH_GATE_MIN_SCORE="${2:-}"; shift 2 ;;
    --fuzz-count)       FUZZ_COUNT="${2:-}"; shift 2 ;;
    --fuzz-seed)        FUZZ_SEED="${2:-}"; shift 2 ;;
    --fuzz-mode)        FUZZ_MODE="${2:-}"; shift 2 ;;
    --fuzz-mutation-budget) FUZZ_MUTATION_BUDGET="${2:-}"; shift 2 ;;
    --fuzz-fidelity-min-score) FUZZ_FIDELITY_MIN_SCORE="${2:-}"; shift 2 ;;
    --adversary-runs)   ADVERSARY_RUNS="${2:-}"; shift 2 ;;
    --adversary-count)  ADVERSARY_COUNT="${2:-}"; shift 2 ;;
    --siem-wazuh-runs)  SIEM_WAZUH_RUNS="${2:-}"; shift 2 ;;
    --matrix-runs)      MATRIX_RUNS="${2:-}"; shift 2 ;;
    --max-cycles)       MAX_CYCLES="${2:-}"; shift 2 ;;
    -h|--help)          usage; exit 0 ;;
    *)                  echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "error: virtualenv python not found at ${PYTHON_BIN}" >&2
  exit 1
fi

for v in DURATION_HOURS INTEGRATION_RUNS SNAPSHOT_RUNS SYNTH_COUNT SYNTH_SEED SYNTH_MUTATION_BUDGET SYNTH_FIDELITY_MIN_SCORE LAUNCH_GATE_MIN_SCORE FUZZ_COUNT FUZZ_SEED FUZZ_MUTATION_BUDGET FUZZ_FIDELITY_MIN_SCORE ADVERSARY_RUNS ADVERSARY_COUNT SIEM_WAZUH_RUNS MATRIX_RUNS MAX_CYCLES; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "error: ${v} must be a non-negative integer" >&2
    exit 2
  fi
done
if [[ "${DURATION_HOURS}" -eq 0 ]]; then
  echo "error: --duration-hours must be greater than zero" >&2
  exit 2
fi
if [[ "${SYNTH_MODE}" != "realistic" && "${SYNTH_MODE}" != "bootstrap" ]]; then
  echo "error: --synth-mode must be realistic or bootstrap" >&2
  exit 2
fi
if [[ "${FUZZ_MODE}" != "realistic" && "${FUZZ_MODE}" != "chaos" ]]; then
  echo "error: --fuzz-mode must be realistic or chaos" >&2
  exit 2
fi

launch_gate_args=()
if [[ "${REQUIRE_LAUNCH_GATE}" -eq 1 ]]; then
  launch_gate_args=(--require-launch-gate --launch-gate-min-score "${LAUNCH_GATE_MIN_SCORE}")
fi

sanitize_label() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._-' '-'
}

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_LABEL="$(sanitize_label "${LABEL}")"
if [[ -n "${SAFE_LABEL}" ]]; then
  RUN_DIR="${OUTPUT_ROOT}/${RUN_ID}-${SAFE_LABEL}"
else
  RUN_DIR="${OUTPUT_ROOT}/${RUN_ID}"
fi
LOG_DIR="${RUN_DIR}/logs"
mkdir -p "${LOG_DIR}"

RUN_LOG="${RUN_DIR}/run.log"
RESULTS_TSV="${RUN_DIR}/results.tsv"
SUMMARY_TXT="${RUN_DIR}/summary.txt"
MANIFEST_TXT="${RUN_DIR}/manifest.txt"
PID_FILE="${RUN_DIR}/pid.txt"

iso_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log() {
  local message="$1"
  printf '[%s] %s\n' "$(iso_now)" "${message}" | tee -a "${RUN_LOG}"
}

printf '%s\n' "$$" >"${PID_FILE}"
printf 'cycle\tstage\titeration\texit_code\tstatus\tduration_sec\tstarted_at\tended_at\tlog_path\n' >"${RESULTS_TSV}"

BRANCH="$(git -C "${ROOT_DIR}" rev-parse --abbrev-ref HEAD || echo "unknown")"
COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD || echo "unknown")"
DIRTY_STATUS="$(git -C "${ROOT_DIR}" status --porcelain || true)"
if [[ -n "${DIRTY_STATUS}" ]]; then
  DIRTY_FLAG="yes"
else
  DIRTY_FLAG="no"
fi

START_TS="$(iso_now)"
START_EPOCH="$(date -u +%s)"
DEADLINE_EPOCH="$((START_EPOCH + (DURATION_HOURS * 3600)))"
DEADLINE_TS="$(date -u -d "@${DEADLINE_EPOCH}" +"%Y-%m-%dT%H:%M:%SZ")"

cat >"${MANIFEST_TXT}" <<EOF
run_id=${RUN_ID}
run_dir=${RUN_DIR}
started_at=${START_TS}
deadline_at=${DEADLINE_TS}
branch=${BRANCH}
commit=${COMMIT}
git_dirty=${DIRTY_FLAG}
duration_hours=${DURATION_HOURS}
integration_runs_per_cycle=${INTEGRATION_RUNS}
snapshot_runs_per_cycle=${SNAPSHOT_RUNS}
synth_count_per_cycle=${SYNTH_COUNT}
synth_seed=${SYNTH_SEED}
synth_mode=${SYNTH_MODE}
synth_mutation_budget=${SYNTH_MUTATION_BUDGET}
synth_fidelity_min_score=${SYNTH_FIDELITY_MIN_SCORE}
fuzz_count_per_cycle=${FUZZ_COUNT}
fuzz_seed=${FUZZ_SEED}
fuzz_mode=${FUZZ_MODE}
fuzz_mutation_budget=${FUZZ_MUTATION_BUDGET}
fuzz_fidelity_min_score=${FUZZ_FIDELITY_MIN_SCORE}
adversary_runs_per_cycle=${ADVERSARY_RUNS}
adversary_count_per_scenario=${ADVERSARY_COUNT}
siem_wazuh_runs_per_cycle=${SIEM_WAZUH_RUNS}
require_launch_gate=${REQUIRE_LAUNCH_GATE}
launch_gate_min_score=${LAUNCH_GATE_MIN_SCORE}
matrix_runs_per_cycle=${MATRIX_RUNS}
max_cycles=${MAX_CYCLES}
host=$(hostname)
kernel=$(uname -sr)
python_bin=${PYTHON_BIN}
EOF

step_total=0
step_fail=0
stop_requested=0
stop_reason="deadline"

on_stop_signal() {
  stop_requested=1
  stop_reason="signal"
  log "Stop signal received; ending soak after current step."
}
trap on_stop_signal INT TERM

is_expected_exit_code() {
  local stage="$1"
  local exit_code="$2"
  case "${stage}" in
    snapshot)
      [[ "${exit_code}" -eq 0 || "${exit_code}" -eq 2 ]]
      ;;
    *)
      [[ "${exit_code}" -eq 0 ]]
      ;;
  esac
}

record_step() {
  local cycle="$1"
  local stage="$2"
  local iter="$3"
  local exit_code="$4"
  local status="$5"
  local duration="$6"
  local started="$7"
  local ended="$8"
  local log_path="$9"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${cycle}" "${stage}" "${iter}" "${exit_code}" "${status}" "${duration}" "${started}" "${ended}" "${log_path}" \
    >>"${RESULTS_TSV}"
}

run_step_cmd() {
  local cycle="$1"
  local stage="$2"
  local iter="$3"
  local log_file="$4"
  shift 4
  local started_epoch ended_epoch duration ec started_ts ended_ts status
  started_epoch="$(date -u +%s)"
  started_ts="$(iso_now)"
  set +e
  "$@" >"${log_file}" 2>&1
  ec=$?
  set -e
  ended_epoch="$(date -u +%s)"
  ended_ts="$(iso_now)"
  duration="$((ended_epoch - started_epoch))"
  step_total="$((step_total + 1))"
  if is_expected_exit_code "${stage}" "${ec}"; then
    status="PASS"
    if [[ "${ec}" -eq 0 ]]; then
      log "PASS cycle=${cycle} stage=${stage} iter=${iter} sec=${duration}"
    else
      log "PASS cycle=${cycle} stage=${stage} iter=${iter} sec=${duration} ec=${ec}"
    fi
  else
    status="FAIL"
    step_fail="$((step_fail + 1))"
    log "FAIL cycle=${cycle} stage=${stage} iter=${iter} ec=${ec} log=${log_file}"
  fi
  record_step "${cycle}" "${stage}" "${iter}" "${ec}" "${status}" "${duration}" "${started_ts}" "${ended_ts}" "${log_file}"
  [[ "${status}" = "PASS" ]]
}

USE_SUDO_DOCKER=0
if docker info >/dev/null 2>&1; then
  USE_SUDO_DOCKER=0
elif [[ -n "${SOAK_SUDO_PASSWORD:-}" ]]; then
  if printf '%s\n' "${SOAK_SUDO_PASSWORD}" | sudo -S docker info >/dev/null 2>&1; then
    USE_SUDO_DOCKER=1
  else
    echo "error: unable to access docker even with sudo" >&2
    exit 1
  fi
else
  echo "error: docker socket unavailable. Set SOAK_SUDO_PASSWORD or add user to docker group." >&2
  exit 1
fi

docker_exec() {
  if [[ "${USE_SUDO_DOCKER}" -eq 1 ]]; then
    printf '%s\n' "${SOAK_SUDO_PASSWORD}" | sudo -S docker "$@"
  else
    docker "$@"
  fi
}

run_snapshot_determinism_cycle() {
  local cycle="$1"
  local snapshot_dir="${RUN_DIR}/snapshots/cycle-${cycle}"
  mkdir -p "${snapshot_dir}"

  local fail_local=0
  local i scan_exit log_file snapshot_file status
  for ((i=1; i<=SNAPSHOT_RUNS; i++)); do
    log_file="${LOG_DIR}/cycle-${cycle}-snapshot-${i}.log"
    snapshot_file="${snapshot_dir}/snapshot-${i}.json"
    local started_epoch started_ts ended_epoch ended_ts duration
    started_epoch="$(date -u +%s)"
    started_ts="$(iso_now)"

    scan_exit=0
    "${PYTHON_BIN}" -m foxclaw scan \
      --profile "${ROOT_DIR}/tests/fixtures/firefox_profile" \
      --ruleset "${ROOT_DIR}/foxclaw/rulesets/balanced.yml" \
      --snapshot-out "${snapshot_file}" >"${log_file}" 2>&1 || scan_exit=$?

    ended_epoch="$(date -u +%s)"
    ended_ts="$(iso_now)"
    duration="$((ended_epoch - started_epoch))"
    step_total="$((step_total + 1))"
    if is_expected_exit_code "snapshot" "${scan_exit}"; then
      status="PASS"
      log "PASS cycle=${cycle} stage=snapshot iter=${i} sec=${duration} ec=${scan_exit}"
    else
      status="FAIL"
      step_fail="$((step_fail + 1))"
      fail_local=1
      log "FAIL cycle=${cycle} stage=snapshot iter=${i} ec=${scan_exit} log=${log_file}"
    fi
    record_step "${cycle}" "snapshot" "${i}" "${scan_exit}" "${status}" "${duration}" "${started_ts}" "${ended_ts}" "${log_file}"
  done

  local sha_file="${snapshot_dir}/sha256.txt"
  sha256sum "${snapshot_dir}"/snapshot-*.json >"${sha_file}"
  local unique_hash_count
  unique_hash_count="$(cut -d' ' -f1 "${sha_file}" | sort -u | wc -l | tr -d ' ')"

  local check_log="${LOG_DIR}/cycle-${cycle}-snapshot-hash-check.log"
  {
    echo "snapshot_dir=${snapshot_dir}"
    echo "unique_hash_count=${unique_hash_count}"
    cat "${sha_file}"
  } >"${check_log}"

  step_total="$((step_total + 1))"
  if [[ "${unique_hash_count}" -ne 1 ]]; then
    step_fail="$((step_fail + 1))"
    fail_local=1
    log "FAIL cycle=${cycle} stage=snapshot_hash_check unique_hashes=${unique_hash_count}"
    record_step "${cycle}" "snapshot_hash_check" "1" "1" "FAIL" "0" "$(iso_now)" "$(iso_now)" "${check_log}"
  else
    log "PASS cycle=${cycle} stage=snapshot_hash_check unique_hashes=1"
    record_step "${cycle}" "snapshot_hash_check" "1" "0" "PASS" "0" "$(iso_now)" "$(iso_now)" "${check_log}"
  fi

  return "${fail_local}"
}

run_matrix_cycle() {
  local cycle="$1"
  local matrix_iter="$2"
  local channel build_log version_log scan_log
  local fail_local=0

  for channel in esr beta nightly; do
    build_log="${LOG_DIR}/cycle-${cycle}-matrix-${matrix_iter}-${channel}-build.log"
    version_log="${LOG_DIR}/cycle-${cycle}-matrix-${matrix_iter}-${channel}-version.log"
    scan_log="${LOG_DIR}/cycle-${cycle}-matrix-${matrix_iter}-${channel}-scan.log"

    run_step_cmd "${cycle}" "matrix_build_${channel}" "${matrix_iter}" "${build_log}" \
      docker_exec build --build-arg FIREFOX_CHANNEL="${channel}" \
      -f "${ROOT_DIR}/docker/testbed/Dockerfile" \
      -t "foxclaw-firefox-testbed:${channel}" \
      "${ROOT_DIR}" || fail_local=1

    run_step_cmd "${cycle}" "matrix_version_${channel}" "${matrix_iter}" "${version_log}" \
      docker_exec run --rm "foxclaw-firefox-testbed:${channel}" firefox --version || fail_local=1

    run_step_cmd "${cycle}" "matrix_scan_${channel}" "${matrix_iter}" "${scan_log}" \
      docker_exec run --rm \
        --user "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -v "${ROOT_DIR}:/workspace" \
        -w /workspace \
        "foxclaw-firefox-testbed:${channel}" \
        bash -lc "scripts/container_workspace_exec.sh scripts/firefox_container_scan.sh --output-dir /tmp/firefox-container-artifacts-${channel}" || fail_local=1
  done

  return "${fail_local}"
}

log "Soak run initialized."
log "Run directory: ${RUN_DIR}"
log "Deadline: ${DEADLINE_TS}"
log "Branch/commit: ${BRANCH} @ ${COMMIT}"

cycle=1
overall_fail=0
while true; do
  if [[ "${stop_requested}" -eq 1 ]]; then
    overall_fail=1
    log "Stopping soak due to received signal."
    break
  fi

  if [[ "$(date -u +%s)" -ge "${DEADLINE_EPOCH}" ]]; then
    stop_reason="deadline"
    log "Reached configured deadline (${DEADLINE_TS}); ending soak."
    break
  fi

  if [[ "${MAX_CYCLES}" -gt 0 && "${cycle}" -gt "${MAX_CYCLES}" ]]; then
    stop_reason="max_cycles"
    log "Reached max cycles (${MAX_CYCLES}); ending soak."
    break
  fi

  log "Starting cycle ${cycle}."

  for ((i=1; i<=INTEGRATION_RUNS; i++)); do
    run_step_cmd "${cycle}" "integration" "${i}" "${LOG_DIR}/cycle-${cycle}-integration-${i}.log" \
      make -C "${ROOT_DIR}" test-integration || overall_fail=1
    if [[ "${stop_requested}" -eq 1 ]]; then
      overall_fail=1
      break
    fi
  done
  if [[ "${stop_requested}" -eq 1 ]]; then
    break
  fi

  if ! run_snapshot_determinism_cycle "${cycle}"; then
    overall_fail=1
  fi
  if [[ "${stop_requested}" -eq 1 ]]; then
    overall_fail=1
    break
  fi

  run_step_cmd "${cycle}" "trust_scan" "1" "${LOG_DIR}/cycle-${cycle}-trust-scan.log" \
    "${ROOT_DIR}/scripts/trust_scan_smoke.sh" "${PYTHON_BIN}" || overall_fail=1
  if [[ "${stop_requested}" -eq 1 ]]; then
    overall_fail=1
    break
  fi

  synth_cycle_dir="${RUN_DIR}/synth/cycle-${cycle}"
  mkdir -p "${synth_cycle_dir}"
  run_step_cmd "${cycle}" "synth" "1" "${LOG_DIR}/cycle-${cycle}-synth.log" \
    "${ROOT_DIR}/scripts/synth_runner.sh" \
    --count "${SYNTH_COUNT}" \
    --output-dir "${synth_cycle_dir}" \
    --mode "${SYNTH_MODE}" \
    --seed "${SYNTH_SEED}" \
    --mutation-budget "${SYNTH_MUTATION_BUDGET}" \
    --fidelity-min-score "${SYNTH_FIDELITY_MIN_SCORE}" \
    "${launch_gate_args[@]}" || overall_fail=1
  if [[ "${stop_requested}" -eq 1 ]]; then
    overall_fail=1
    break
  fi

  fuzz_cycle_dir="${RUN_DIR}/fuzz/cycle-${cycle}"
  mkdir -p "${fuzz_cycle_dir}"
  run_step_cmd "${cycle}" "fuzz" "1" "${LOG_DIR}/cycle-${cycle}-fuzz.log" \
    "${ROOT_DIR}/scripts/fuzz_runner.sh" \
    --count "${FUZZ_COUNT}" \
    --output-dir "${fuzz_cycle_dir}" \
    --mode "${FUZZ_MODE}" \
    --seed "${FUZZ_SEED}" \
    --mutation-budget "${FUZZ_MUTATION_BUDGET}" \
    --fidelity-min-score "${FUZZ_FIDELITY_MIN_SCORE}" \
    "${launch_gate_args[@]}" || overall_fail=1
  if [[ "${stop_requested}" -eq 1 ]]; then
    overall_fail=1
    break
  fi

  for ((a=1; a<=ADVERSARY_RUNS; a++)); do
    adversary_cycle_dir="${RUN_DIR}/adversary/cycle-${cycle}-run-${a}"
    mkdir -p "${adversary_cycle_dir}"
    adversary_seed="$((606060 + (cycle * 100) + a))"
    run_step_cmd "${cycle}" "adversary" "${a}" "${LOG_DIR}/cycle-${cycle}-adversary-${a}.log" \
      "${PYTHON_BIN}" "${ROOT_DIR}/scripts/adversary_profiles.py" \
      --output-dir "${adversary_cycle_dir}" \
      --count-per-scenario "${ADVERSARY_COUNT}" \
      --seed "${adversary_seed}" \
      --mutation-budget 3 \
      --max-mutation-severity high \
      --ruleset "${ROOT_DIR}/foxclaw/rulesets/strict.yml" \
      --quiet || overall_fail=1
    if [[ "${stop_requested}" -eq 1 ]]; then
      overall_fail=1
      break
    fi
  done
  if [[ "${stop_requested}" -eq 1 ]]; then
    break
  fi

  for ((s=1; s<=SIEM_WAZUH_RUNS; s++)); do
    siem_cycle_dir="${RUN_DIR}/siem-wazuh/cycle-${cycle}-run-${s}"
    mkdir -p "${siem_cycle_dir}"
    run_step_cmd "${cycle}" "siem_wazuh" "${s}" "${LOG_DIR}/cycle-${cycle}-siem-wazuh-${s}.log" \
      "${PYTHON_BIN}" "${ROOT_DIR}/scripts/siem_wazuh_smoke.py" \
      --output-dir "${siem_cycle_dir}" \
      --python-bin "${PYTHON_BIN}" || overall_fail=1
    if [[ "${stop_requested}" -eq 1 ]]; then
      overall_fail=1
      break
    fi
  done
  if [[ "${stop_requested}" -eq 1 ]]; then
    break
  fi

  for ((m=1; m<=MATRIX_RUNS; m++)); do
    if ! run_matrix_cycle "${cycle}" "${m}"; then
      overall_fail=1
    fi
    if [[ "${stop_requested}" -eq 1 ]]; then
      overall_fail=1
      break
    fi
  done
  if [[ "${stop_requested}" -eq 1 ]]; then
    break
  fi

  log "Finished cycle ${cycle}."
  cycle="$((cycle + 1))"
done

END_TS="$(iso_now)"
END_EPOCH="$(date -u +%s)"
TOTAL_SEC="$((END_EPOCH - START_EPOCH))"
CYCLE_COUNT="$((cycle - 1))"
STEP_PASS="$((step_total - step_fail))"

{
  echo "run_id=${RUN_ID}"
  echo "run_dir=${RUN_DIR}"
  echo "started_at=${START_TS}"
  echo "ended_at=${END_TS}"
  echo "duration_seconds=${TOTAL_SEC}"
  echo "cycles_completed=${CYCLE_COUNT}"
  echo "steps_total=${step_total}"
  echo "steps_passed=${STEP_PASS}"
  echo "steps_failed=${step_fail}"
  echo "stop_reason=${stop_reason}"
  echo "overall_status=$([[ ${overall_fail} -eq 0 ]] && echo PASS || echo FAIL)"
  echo "manifest=${MANIFEST_TXT}"
  echo "results=${RESULTS_TSV}"
  echo "run_log=${RUN_LOG}"
  echo "logs_dir=${LOG_DIR}"
} >"${SUMMARY_TXT}"

if [[ "${overall_fail}" -eq 0 ]]; then
  log "Soak completed successfully. Summary: ${SUMMARY_TXT}"
  exit 0
fi

log "Soak completed with failures. Summary: ${SUMMARY_TXT}"
exit 1
