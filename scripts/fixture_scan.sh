#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <python-bin>" >&2
  exit 1
fi

python_bin="$1"
scan_exit=0

"${python_bin}" -m foxclaw scan \
  --profile tests/fixtures/firefox_profile \
  --ruleset foxclaw/rulesets/balanced.yml \
  --output foxclaw.json \
  --sarif-out foxclaw.sarif \
  --deterministic || scan_exit=$?

echo "foxclaw scan exit code: ${scan_exit}"
if [[ "${scan_exit}" -ne 0 && "${scan_exit}" -ne 2 ]]; then
  exit "${scan_exit}"
fi

"${python_bin}" - <<'PY'
import json

for path in ("foxclaw.json", "foxclaw.sarif"):
    with open(path, "r", encoding="utf-8") as handle:
        json.load(handle)

print("json+sarif parse ok")
PY
