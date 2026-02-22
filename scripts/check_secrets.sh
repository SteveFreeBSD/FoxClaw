#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

output_file="$(mktemp)"
trap 'rm -f "${output_file}"' EXIT

PYTHON_BIN="python"
if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
fi
scan_cmd=()
if [[ -x "${ROOT_DIR}/.venv/bin/detect-secrets" ]]; then
  scan_cmd=("${ROOT_DIR}/.venv/bin/detect-secrets")
elif command -v detect-secrets >/dev/null 2>&1; then
  scan_cmd=("detect-secrets")
else
  scan_cmd=("${PYTHON_BIN}" "-m" "detect_secrets")
fi

# Deterministic fixture artifacts intentionally embed checksums/identifiers and
# trigger entropy-based false positives.
readonly SCAN_EXCLUDE_FILES='^tests/fixtures/testbed/manifest\.json$|^tests/fixtures/migration_contracts/.*$'

"${scan_cmd[@]}" scan \
  --exclude-files "${SCAN_EXCLUDE_FILES}" \
  $(git ls-files) > "${output_file}"

"${PYTHON_BIN}" - <<'PY' "${output_file}"
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
results = payload.get("results", {})
if results:
    raise SystemExit("detect-secrets reported potential secrets")
print("[secrets] clean.")
PY
