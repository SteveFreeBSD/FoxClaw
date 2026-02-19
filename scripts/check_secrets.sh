#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

output_file="$(mktemp)"
trap 'rm -f "${output_file}"' EXIT

.venv/bin/detect-secrets scan $(git ls-files) > "${output_file}"

.venv/bin/python - <<'PY' "${output_file}"
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
results = payload.get("results", {})
if results:
    raise SystemExit("detect-secrets reported potential secrets")
print("[secrets] clean.")
PY
