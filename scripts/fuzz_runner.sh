#!/usr/bin/env bash
# --------------------------------------------------------------------------
# fuzz_runner.sh — Generate random profiles and run FoxClaw against them.
#
# Generates N randomly corrupted profiles using fuzz_profiles.py and runs FoxClaw
# across all of them to ensure it exits with expected status codes without crashing.
# --------------------------------------------------------------------------
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/fuzz_runner.sh [--count <N>]
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
FUZZ_PROFILES_SCRIPT="${ROOT_DIR}/scripts/fuzz_profiles.py"
OUTPUT_DIR="/tmp/foxclaw-fuzzer-profiles"
RULESET_PATH="${ROOT_DIR}/foxclaw/rulesets/strict.yml"
COUNT=50

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)   COUNT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)         echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "error: cannot find virtualenv python at ${PYTHON_BIN}" >&2
  exit 1
fi

echo "[fuzzer] Cleaning up old profiles..."
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

echo "[fuzzer] Generating ${COUNT} fuzzed profiles..."
"${PYTHON_BIN}" "${FUZZ_PROFILES_SCRIPT}" -n "${COUNT}" --output-dir "${OUTPUT_DIR}" --quiet

echo "[fuzzer] Starting FoxClaw scans..."
failed=0
passed=0

for profile in "${OUTPUT_DIR}"/profile_*; do
    if [[ ! -d "${profile}" ]]; then continue; fi

    scan_exit=0
    scan_output=$("${PYTHON_BIN}" -m foxclaw scan --profile "${profile}" --ruleset "${RULESET_PATH}" --json 2>&1) || scan_exit=$?

    # Expected exit codes:
    # 0 = No findings, scan ok
    # 1 = Generic error (e.g. quiet profile required, broken flags)
    # 2 = Findings discovered
    
    # We must also check that we did not encounter an unhandled Python traceback if the exit code was 1.
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

if [[ "${failed}" -gt 0 ]]; then
    exit 1
fi
exit 0
