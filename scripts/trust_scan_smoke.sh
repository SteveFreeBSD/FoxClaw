#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <python-bin>" >&2
  exit 1
fi

python_bin="$1"
if [[ ! -x "${python_bin}" ]]; then
  echo "error: python binary not found or not executable: ${python_bin}" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE_PATH="${ROOT_DIR}/tests/fixtures/firefox_profile"
RULESET_PATH="${ROOT_DIR}/foxclaw/rulesets/balanced.yml"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

digest="$(sha256sum "${RULESET_PATH}" | awk '{print $1}')"
manifest_ok="${tmpdir}/ruleset-trust-ok.json"
manifest_bad="${tmpdir}/ruleset-trust-bad.json"

cat >"${manifest_ok}" <<EOF
{
  "schema_version": "1.0.0",
  "keys": [],
  "rulesets": [
    {
      "path": "${RULESET_PATH}",
      "sha256": "${digest}"
    }
  ]
}
EOF

cat >"${manifest_bad}" <<EOF
{
  "schema_version": "1.0.0",
  "keys": [],
  "rulesets": [
    {
      "path": "${RULESET_PATH}",
      "sha256": "$(printf '0%.0s' {1..64})"
    }
  ]
}
EOF

scan_exit=0
"${python_bin}" -m foxclaw scan \
  --profile "${PROFILE_PATH}" \
  --ruleset "${RULESET_PATH}" \
  --ruleset-trust-manifest "${manifest_ok}" \
  --json >"${tmpdir}/scan.json" 2>"${tmpdir}/scan.err" || scan_exit=$?

if [[ "${scan_exit}" -ne 0 && "${scan_exit}" -ne 2 ]]; then
  echo "error: trust-manifest scan returned unexpected exit code: ${scan_exit}" >&2
  cat "${tmpdir}/scan.err" >&2 || true
  exit "${scan_exit}"
fi

"${python_bin}" - <<'PY' "${tmpdir}/scan.json"
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = payload["summary"]
if "findings_total" not in summary:
    raise SystemExit("error: missing findings_total in trust scan summary")
print("[trust-scan] scan summary findings_total=", summary["findings_total"])
PY

mismatch_exit=0
"${python_bin}" -m foxclaw scan \
  --profile "${PROFILE_PATH}" \
  --ruleset "${RULESET_PATH}" \
  --ruleset-trust-manifest "${manifest_bad}" \
  --json >"${tmpdir}/mismatch.log" 2>&1 || mismatch_exit=$?

if [[ "${mismatch_exit}" -ne 1 ]]; then
  echo "error: mismatch trust-manifest scan expected exit code 1, got ${mismatch_exit}" >&2
  cat "${tmpdir}/mismatch.log" >&2 || true
  exit 1
fi
if ! grep -q "sha256 mismatch" "${tmpdir}/mismatch.log"; then
  echo "error: mismatch trust-manifest scan missing sha256 mismatch message" >&2
  cat "${tmpdir}/mismatch.log" >&2 || true
  exit 1
fi

signature_exit=0
"${python_bin}" -m foxclaw scan \
  --profile "${PROFILE_PATH}" \
  --ruleset "${RULESET_PATH}" \
  --ruleset-trust-manifest "${manifest_ok}" \
  --require-ruleset-signatures \
  --json >"${tmpdir}/signature-required.log" 2>&1 || signature_exit=$?

if [[ "${signature_exit}" -ne 1 ]]; then
  echo "error: signature-required trust scan expected exit code 1, got ${signature_exit}" >&2
  cat "${tmpdir}/signature-required.log" >&2 || true
  exit 1
fi
if ! grep -q "signatures are required" "${tmpdir}/signature-required.log"; then
  echo "error: signature-required trust scan missing required-signatures message" >&2
  cat "${tmpdir}/signature-required.log" >&2 || true
  exit 1
fi

fleet_exit=0
"${python_bin}" -m foxclaw fleet aggregate \
  --profile "${PROFILE_PATH}" \
  --ruleset "${RULESET_PATH}" \
  --ruleset-trust-manifest "${manifest_ok}" \
  --json >"${tmpdir}/fleet.json" 2>"${tmpdir}/fleet.err" || fleet_exit=$?

if [[ "${fleet_exit}" -ne 0 && "${fleet_exit}" -ne 2 ]]; then
  echo "error: trust-manifest fleet aggregate returned unexpected exit code: ${fleet_exit}" >&2
  cat "${tmpdir}/fleet.err" >&2 || true
  exit "${fleet_exit}"
fi

"${python_bin}" - <<'PY' "${tmpdir}/fleet.json"
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
aggregate = payload["aggregate"]
if aggregate["profiles_total"] != 1:
    raise SystemExit(
        f"error: expected profiles_total=1 for trust fleet smoke, got {aggregate['profiles_total']}"
    )
print("[trust-scan] fleet summary findings_total=", aggregate["findings_total"])
PY

fleet_mismatch_exit=0
"${python_bin}" -m foxclaw fleet aggregate \
  --profile "${PROFILE_PATH}" \
  --ruleset "${RULESET_PATH}" \
  --ruleset-trust-manifest "${manifest_bad}" \
  --json >"${tmpdir}/fleet-mismatch.log" 2>&1 || fleet_mismatch_exit=$?

if [[ "${fleet_mismatch_exit}" -ne 1 ]]; then
  echo "error: mismatch trust-manifest fleet expected exit code 1, got ${fleet_mismatch_exit}" >&2
  cat "${tmpdir}/fleet-mismatch.log" >&2 || true
  exit 1
fi
if ! grep -q "sha256 mismatch" "${tmpdir}/fleet-mismatch.log"; then
  echo "error: mismatch trust-manifest fleet missing sha256 mismatch message" >&2
  cat "${tmpdir}/fleet-mismatch.log" >&2 || true
  exit 1
fi

echo "[trust-scan] complete."
