#!/usr/bin/env bash
# --------------------------------------------------------------------------
# fuzz_runner.sh — Generate randomized profiles and run FoxClaw against them.
#
# Generates realistic profiles plus controlled mutations, gates them with
# fidelity checks, then scans to verify crash resistance.
# --------------------------------------------------------------------------
set -euo pipefail

usage() {
  cat <<'EOF_HELP'
Usage: scripts/fuzz_runner.sh [options]

Options:
  --count <N>                    Number of profiles (default: 50)
  --output-dir <path>            Output directory
  --mode <realistic|chaos>       Fuzz mode (default: chaos)
  --scenario <name>              Force one scenario for all profiles
  --seed <N>                     Deterministic seed (default: 525252)
  --mutation-budget <N>          Base mutation budget (default: 3)
  --max-mutation-severity <S>    Mutation severity cap (default: high)
  --catalog-path <path>          Optional AMO catalog snapshot JSON
  --allow-network-fetch          Allow live AMO fetches for uncached extensions
  --fidelity-min-score <N>       Minimum realism score (default: 50)
  --require-launch-gate          Run headless Firefox against generated profiles
  --launch-gate-min-score <N>    Minimum realism score after Firefox exit (default: 50)
EOF_HELP
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
FUZZ_PROFILES_SCRIPT="${ROOT_DIR}/scripts/fuzz_profiles.py"
FIDELITY_SCRIPT="${ROOT_DIR}/scripts/profile_fidelity_check.py"
LAUNCH_GATE_SCRIPT="${ROOT_DIR}/scripts/profile_launch_gate.py"
OUTPUT_DIR="/tmp/foxclaw-fuzzer-profiles"
RULESET_PATH="${ROOT_DIR}/foxclaw/rulesets/strict.yml"
COUNT=50
MODE="chaos"
SCENARIO=""
SEED=525252
MUTATION_BUDGET=3
MAX_MUTATION_SEVERITY="high"
CATALOG_PATH=""
ALLOW_NETWORK_FETCH=0
FIDELITY_MIN_SCORE=50
REQUIRE_LAUNCH_GATE=0
LAUNCH_GATE_MIN_SCORE=50

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count) COUNT="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --scenario) SCENARIO="${2:-}"; shift 2 ;;
    --seed) SEED="${2:-}"; shift 2 ;;
    --mutation-budget) MUTATION_BUDGET="${2:-}"; shift 2 ;;
    --max-mutation-severity) MAX_MUTATION_SEVERITY="${2:-}"; shift 2 ;;
    --catalog-path) CATALOG_PATH="${2:-}"; shift 2 ;;
    --allow-network-fetch) ALLOW_NETWORK_FETCH=1; shift 1 ;;
    --fidelity-min-score) FIDELITY_MIN_SCORE="${2:-}"; shift 2 ;;
    --require-launch-gate) REQUIRE_LAUNCH_GATE=1; shift 1 ;;
    --launch-gate-min-score) LAUNCH_GATE_MIN_SCORE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "error: cannot find virtualenv python at ${PYTHON_BIN}" >&2
  exit 1
fi

for v in COUNT SEED MUTATION_BUDGET FIDELITY_MIN_SCORE LAUNCH_GATE_MIN_SCORE; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "error: ${v} must be a non-negative integer" >&2
    exit 2
  fi
done

if [[ "${MODE}" != "realistic" && "${MODE}" != "chaos" ]]; then
  echo "error: --mode must be realistic or chaos" >&2
  exit 2
fi

if [[ "${MAX_MUTATION_SEVERITY}" != "low" && "${MAX_MUTATION_SEVERITY}" != "medium" && "${MAX_MUTATION_SEVERITY}" != "high" ]]; then
  echo "error: --max-mutation-severity must be low, medium, or high" >&2
  exit 2
fi

echo "[fuzzer] Cleaning up old profiles..."
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

echo "[fuzzer] Generating ${COUNT} fuzzed profiles..."
gen_cmd=(
  "${PYTHON_BIN}" "${FUZZ_PROFILES_SCRIPT}"
  -n "${COUNT}"
  --output-dir "${OUTPUT_DIR}"
  --mode "${MODE}"
  --seed "${SEED}"
  --mutation-budget "${MUTATION_BUDGET}"
  --max-mutation-severity "${MAX_MUTATION_SEVERITY}"
  --quiet
)
if [[ -n "${SCENARIO}" ]]; then
  gen_cmd+=(--scenario "${SCENARIO}")
fi
if [[ -n "${CATALOG_PATH}" ]]; then
  gen_cmd+=(--catalog-path "${CATALOG_PATH}")
fi
if [[ "${ALLOW_NETWORK_FETCH}" -eq 1 ]]; then
  gen_cmd+=(--allow-network-fetch)
fi
"${gen_cmd[@]}"

echo "[fuzzer] Running profile fidelity gate (min score ${FIDELITY_MIN_SCORE})..."
"${PYTHON_BIN}" "${FIDELITY_SCRIPT}" "${OUTPUT_DIR}" \
  --pattern "profile_*" \
  --min-score "${FIDELITY_MIN_SCORE}" \
  --enforce-min-score \
  --json-out "${OUTPUT_DIR}/fidelity-summary.json"

avg_score="$("${PYTHON_BIN}" - <<'PY' "${OUTPUT_DIR}/fidelity-summary.json"
import json
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
print(payload.get("average_score", 0))
PY
)"

catalog_version="$("${PYTHON_BIN}" - <<'PY' "${OUTPUT_DIR}"
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for profile in sorted(root.glob("profile_*/metadata.json")):
    payload = json.loads(profile.read_text(encoding="utf-8"))
    print(payload.get("catalog_version", "unknown"))
    break
else:
    print("unknown")
PY
)"

launch_stats=""
if [[ "${REQUIRE_LAUNCH_GATE}" -eq 1 ]]; then
  echo "[fuzzer] Running profile launch gate (min post-score ${LAUNCH_GATE_MIN_SCORE})..."
  "${PYTHON_BIN}" "${LAUNCH_GATE_SCRIPT}" "${OUTPUT_DIR}" \
    --pattern "profile_*" \
    --min-post-score "${LAUNCH_GATE_MIN_SCORE}" \
    --enforce \
    --json-out "${OUTPUT_DIR}/launch-gate-summary.json"
    
  launch_stats="$("${PYTHON_BIN}" - <<'PY' "${OUTPUT_DIR}/launch-gate-summary.json"
import json
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
survived = payload.get("profiles_survived", 0)
total = payload.get("profiles_evaluated", 0)
print(f"survived={survived}/{total}")
PY
)"
fi

echo "[fuzzer] Starting FoxClaw scans..."
failed=0
passed=0

for profile in "${OUTPUT_DIR}"/profile_*; do
  if [[ ! -d "${profile}" ]]; then
    continue
  fi

  scan_exit=0
  scan_output=$("${PYTHON_BIN}" -m foxclaw scan --profile "${profile}" --ruleset "${RULESET_PATH}" --json 2>&1) || scan_exit=$?

  is_crash=false
  if [[ "${scan_exit}" -gt 2 ]]; then
    is_crash=true
  elif echo "${scan_output}" | grep -q "Traceback (most recent call last):"; then
    is_crash=true
  fi

  if [[ "${is_crash}" == true ]]; then
    echo "❌ CRASH: profile $(basename "${profile}") (exit ${scan_exit})"
    echo "============================="
    echo "${scan_output}"
    echo "============================="
    failed=$((failed + 1))
  else
    passed=$((passed + 1))
  fi
done

echo ""
echo "[fuzzer] Summary:"
echo "  Passed (no crashes): ${passed}"
echo "  Failed (crashed):    ${failed}"
echo "  Avg realism score:   ${avg_score}"
if [[ -n "${launch_stats}" ]]; then
  echo "  Launch Gate:         ${launch_stats}"
fi
echo "  Provenance: mode=${MODE} seed=${SEED} scenario=${SCENARIO:-auto} catalog=${catalog_version}"

if [[ "${failed}" -gt 0 ]]; then
  exit 1
fi
exit 0
