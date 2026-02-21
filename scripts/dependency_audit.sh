#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/dependency_audit.sh [--output <path>] [--pip-audit-bin <path-or-name>]

Runs pip-audit against the local Python environment and writes JSON output.
Exit code is non-zero when vulnerabilities are detected or execution fails.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${ROOT_DIR}/dependency-audit.json"
PIP_AUDIT_BIN="pip-audit"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_PATH="${2:-}"
      if [[ -z "${OUTPUT_PATH}" ]]; then
        echo "error: --output requires a value." >&2
        exit 2
      fi
      shift 2
      ;;
    --pip-audit-bin)
      PIP_AUDIT_BIN="${2:-}"
      if [[ -z "${PIP_AUDIT_BIN}" ]]; then
        echo "error: --pip-audit-bin requires a value." >&2
        exit 2
      fi
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

cd "${ROOT_DIR}"

if ! command -v "${PIP_AUDIT_BIN}" >/dev/null 2>&1; then
  echo "error: pip-audit executable not found: ${PIP_AUDIT_BIN}" >&2
  echo "install it first (example: .venv/bin/pip install pip-audit)." >&2
  exit 2
fi

output_parent="$(dirname "${OUTPUT_PATH}")"
mkdir -p "${output_parent}"

audit_exit=0
"${PIP_AUDIT_BIN}" --local --desc --format json --output "${OUTPUT_PATH}" || audit_exit=$?

python3 - <<'PY' "${OUTPUT_PATH}"
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
dependencies: list[dict[str, object]] = []
if isinstance(payload, list):
    dependencies = [item for item in payload if isinstance(item, dict)]
elif isinstance(payload, dict):
    raw = payload.get("dependencies", [])
    if isinstance(raw, list):
        dependencies = [item for item in raw if isinstance(item, dict)]

packages_with_vulns = 0
vulnerabilities_total = 0
for dependency in dependencies:
    vulns = dependency.get("vulns", [])
    if not isinstance(vulns, list):
        continue
    if vulns:
        packages_with_vulns += 1
        vulnerabilities_total += len(vulns)

print(f"[dependency-audit] output={Path(sys.argv[1]).resolve()}")
print(f"[dependency-audit] packages_with_vulns={packages_with_vulns}")
print(f"[dependency-audit] vulnerabilities_total={vulnerabilities_total}")
PY

if [[ "${audit_exit}" -ne 0 ]]; then
  echo "dependency vulnerabilities detected; inspect ${OUTPUT_PATH}." >&2
fi

exit "${audit_exit}"
