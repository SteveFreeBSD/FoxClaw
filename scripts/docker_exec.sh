#!/usr/bin/env bash
set -euo pipefail

use_sudo="${FOXCLAW_USE_SUDO_DOCKER:-0}"

if [[ "${use_sudo}" -eq 1 ]]; then
  if [[ -z "${SOAK_SUDO_PASSWORD:-}" ]]; then
    echo "error: SOAK_SUDO_PASSWORD is required when FOXCLAW_USE_SUDO_DOCKER=1" >&2
    exit 2
  fi
  printf '%s\n' "${SOAK_SUDO_PASSWORD}" | sudo -S docker "$@"
else
  exec docker "$@"
fi
