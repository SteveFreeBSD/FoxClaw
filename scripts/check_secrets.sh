#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

output_file="$(mktemp)"
trap 'rm -f "${output_file}"' EXIT

# Fixture manifests and generated session-memory journals intentionally store
# SHA-256/commit hashes and trigger false positives on entropy-based detectors.
readonly DETECT_SECRETS_EXCLUDE_FILES='^(tests/fixtures/(testbed/manifest\.json|migration_contracts/manifest\.json|windows_share/stage-manifest\.json)|docs/SESSION_MEMORY\.jsonl)$'

.venv/bin/detect-secrets scan \
  --exclude-files "${DETECT_SECRETS_EXCLUDE_FILES}" \
  $(git ls-files) > "${output_file}"

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
