#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/firefox_container_scan.sh [--python <python-bin>] [--firefox <firefox-bin>] [--profile-dir <dir>] [--output-dir <dir>] [--ruleset <path>]

Generates a real Firefox profile in headless mode and runs a FoxClaw scan against it.
This script is intended for containerized nightly/dispatch smoke coverage.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="python"
FIREFOX_BIN="firefox"
PROFILE_DIR="/tmp/foxclaw-firefox-profile"
OUTPUT_DIR="/tmp/foxclaw-firefox-artifacts"
RULESET_PATH="foxclaw/rulesets/balanced.yml"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python)
      PYTHON_BIN="${2:-}"
      shift 2
      ;;
    --firefox)
      FIREFOX_BIN="${2:-}"
      shift 2
      ;;
    --profile-dir)
      PROFILE_DIR="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --ruleset)
      RULESET_PATH="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${PYTHON_BIN}" || -z "${FIREFOX_BIN}" ]]; then
  echo "error: --python and --firefox require values." >&2
  exit 2
fi
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "error: python binary not found: ${PYTHON_BIN}" >&2
  exit 2
fi
if ! command -v "${FIREFOX_BIN}" >/dev/null 2>&1; then
  echo "error: firefox binary not found: ${FIREFOX_BIN}" >&2
  exit 2
fi

cd "${ROOT_DIR}"
rm -rf "${PROFILE_DIR}" "${OUTPUT_DIR}"
mkdir -p "${PROFILE_DIR}" "${OUTPUT_DIR}"

policy_path="${OUTPUT_DIR}/policies.json"
cat > "${policy_path}" <<'JSON'
{
  "policies": {
    "DisableTelemetry": true
  }
}
JSON

firefox_log="${OUTPUT_DIR}/firefox-headless.log"
firefox_exit=0
if command -v timeout >/dev/null 2>&1; then
  timeout 45s "${FIREFOX_BIN}" --headless --no-remote --profile "${PROFILE_DIR}" about:blank >"${firefox_log}" 2>&1 || firefox_exit=$?
  if [[ "${firefox_exit}" -ne 0 && "${firefox_exit}" -ne 124 ]]; then
    echo "error: firefox headless launch failed (exit=${firefox_exit})." >&2
    cat "${firefox_log}" >&2 || true
    exit "${firefox_exit}"
  fi
else
  "${FIREFOX_BIN}" --headless --no-remote --profile "${PROFILE_DIR}" about:blank >"${firefox_log}" 2>&1 || firefox_exit=$?
  if [[ "${firefox_exit}" -ne 0 ]]; then
    echo "error: firefox headless launch failed (exit=${firefox_exit})." >&2
    cat "${firefox_log}" >&2 || true
    exit "${firefox_exit}"
  fi
fi

if [[ ! -f "${PROFILE_DIR}/prefs.js" ]]; then
  echo "error: firefox did not create prefs.js in profile directory." >&2
  cat "${firefox_log}" >&2 || true
  exit 1
fi

"${PYTHON_BIN}" - <<'PY' "${PROFILE_DIR}"
import sqlite3
import sys
from pathlib import Path

profile = Path(sys.argv[1])
for db_name in ("places.sqlite", "cookies.sqlite"):
    db_path = profile / db_name
    if db_path.exists():
        continue
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, note TEXT)")
    conn.execute("INSERT INTO t(note) VALUES (?)", ("container-smoke",))
    conn.commit()
    conn.close()
PY

scan_exit=0
"${PYTHON_BIN}" -m foxclaw scan \
  --profile "${PROFILE_DIR}" \
  --ruleset "${RULESET_PATH}" \
  --intel-store-dir "${INTEL_DIR}" \
  --output "${OUTPUT_DIR}/foxclaw.json" \
  --sarif-out "${OUTPUT_DIR}/foxclaw.sarif" \
  --snapshot-out "${OUTPUT_DIR}/foxclaw.snapshot.json" \
  --deterministic || scan_exit=$?

if [[ "${scan_exit}" -ne 0 && "${scan_exit}" -ne 2 ]]; then
  echo "error: foxclaw scan returned unexpected exit code: ${scan_exit}" >&2
  exit "${scan_exit}"
fi

"${PYTHON_BIN}" - <<'PY' "${OUTPUT_DIR}/foxclaw.json" "${OUTPUT_DIR}/foxclaw.sarif" "${OUTPUT_DIR}/foxclaw.snapshot.json"
import json
import sys
from pathlib import Path

json_path, sarif_path, snapshot_path = [Path(arg) for arg in sys.argv[1:4]]
json_payload = json.loads(json_path.read_text(encoding="utf-8"))
json.loads(sarif_path.read_text(encoding="utf-8"))
json.loads(snapshot_path.read_text(encoding="utf-8"))

summary = json_payload["summary"]
print("[container-smoke] findings_total:", summary["findings_total"])
print("[container-smoke] findings_high_count:", summary["findings_high_count"])
print("[container-smoke] policies_found:", summary["policies_found"])
PY

echo "[container-smoke] outputs written to ${OUTPUT_DIR}."
