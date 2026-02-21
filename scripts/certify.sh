#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/certify.sh [--with-live-profile] [--profile <path>] [--python <python-bin>]

Runs FoxClaw local certification gates:
  - lint, typecheck, tests
  - integration testbed suite + deterministic fixture validation
  - fixture scan (+ JSON/SARIF parse)
  - ruleset trust smoke checks (positive and fail-closed paths)
  - security/dead-code scans (bandit, vulture, detect-secrets)
  - optional live Firefox profile scan and snapshot diff smoke test
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
WITH_LIVE_PROFILE=0
PROFILE_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-live-profile)
      WITH_LIVE_PROFILE=1
      shift
      ;;
    --profile)
      PROFILE_PATH="${2:-}"
      if [[ -z "${PROFILE_PATH}" ]]; then
        echo "error: --profile requires a value." >&2
        exit 2
      fi
      shift 2
      ;;
    --python)
      PYTHON_BIN="${2:-}"
      if [[ -z "${PYTHON_BIN}" ]]; then
        echo "error: --python requires a value." >&2
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

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "error: python binary not found or not executable: ${PYTHON_BIN}" >&2
  exit 2
fi

cd "${ROOT_DIR}"

echo "[certify] lint."
.venv/bin/ruff check .

echo "[certify] typecheck."
.venv/bin/mypy foxclaw

echo "[certify] test."
.venv/bin/pytest -q -m "not integration"

echo "[certify] testbed-fixtures-write."
"${PYTHON_BIN}" ./scripts/generate_testbed_fixtures.py --write

echo "[certify] testbed-fixtures-check."
"${PYTHON_BIN}" ./scripts/generate_testbed_fixtures.py --check

echo "[certify] testbed-fixtures-clean."
if ! git diff --quiet -- tests/fixtures/testbed; then
  echo "error: deterministic testbed fixtures are out of date. run make testbed-fixtures-write and commit updates." >&2
  git --no-pager diff -- tests/fixtures/testbed >&2 || true
  exit 1
fi

echo "[certify] test-integration."
.venv/bin/pytest -q -m integration

echo "[certify] fixture-scan."
./scripts/fixture_scan.sh "${PYTHON_BIN}"

echo "[certify] trust-scan."
./scripts/trust_scan_smoke.sh "${PYTHON_BIN}"

echo "[certify] bandit."
.venv/bin/bandit -q -r foxclaw -x tests

echo "[certify] vulture."
.venv/bin/vulture foxclaw tests --min-confidence 80

echo "[certify] detect-secrets."
./scripts/check_secrets.sh

if [[ "${WITH_LIVE_PROFILE}" -eq 1 ]]; then
  echo "[certify] live-profile scan smoke."
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  scan_args=(--ruleset foxclaw/rulesets/balanced.yml)
  if [[ -n "${PROFILE_PATH}" ]]; then
    scan_args+=(--profile "${PROFILE_PATH}")
  fi

  scan_exit_a=0
  scan_exit_b=0
  "${PYTHON_BIN}" -m foxclaw scan "${scan_args[@]}" --snapshot-out "${tmpdir}/a.snapshot.json" || scan_exit_a=$?
  "${PYTHON_BIN}" -m foxclaw scan "${scan_args[@]}" --snapshot-out "${tmpdir}/b.snapshot.json" || scan_exit_b=$?

  if [[ "${scan_exit_a}" -ne 0 && "${scan_exit_a}" -ne 2 ]]; then
    echo "error: live scan A returned unexpected exit code: ${scan_exit_a}" >&2
    exit "${scan_exit_a}"
  fi
  if [[ "${scan_exit_b}" -ne 0 && "${scan_exit_b}" -ne 2 ]]; then
    echo "error: live scan B returned unexpected exit code: ${scan_exit_b}" >&2
    exit "${scan_exit_b}"
  fi

  "${PYTHON_BIN}" -m foxclaw snapshot diff \
    --before "${tmpdir}/a.snapshot.json" \
    --after "${tmpdir}/b.snapshot.json" \
    --json > "${tmpdir}/diff.json"

  "${PYTHON_BIN}" - <<'PY' "${tmpdir}/diff.json"
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = payload["summary"]
print("[certify] live diff drift_detected:", summary["drift_detected"])
print("[certify] live diff added/removed/changed:",
      summary["added_findings_count"],
      summary["removed_findings_count"],
      summary["changed_findings_count"])
PY
fi

echo "[certify] cleanup."
make clean

echo "[certify] complete."
