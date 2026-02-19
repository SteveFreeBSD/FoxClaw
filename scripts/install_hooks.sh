#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ ! -f .githooks/pre-push ]]; then
  echo "error: expected hook file missing: .githooks/pre-push" >&2
  exit 1
fi

chmod +x .githooks/pre-push
git config core.hooksPath .githooks

echo "Installed Git hooks path: .githooks"
echo "Pre-push gate: ./scripts/certify.sh"
