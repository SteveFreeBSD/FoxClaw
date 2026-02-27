#!/usr/bin/env bash
# --------------------------------------------------------------------------
# container_workspace_exec.sh — run a FoxClaw container script from a writable
# temporary workspace copy.
#
# This avoids mutating /workspace (host-mounted repo) and prevents failures
# when host files are read-only or owned by a different UID/GID.
# --------------------------------------------------------------------------
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/container_workspace_exec.sh [options] <entry-script> [entry-args...]

Options:
  --workspace <path>   Mounted source workspace (default: /workspace)
  -h, --help           Show help.

Example:
  scripts/container_workspace_exec.sh \
    scripts/firefox_container_scan.sh \
    --output-dir /workspace/firefox-container-artifacts
EOF
}

WORKSPACE_DIR="/workspace"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)
      WORKSPACE_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -lt 1 ]]; then
  echo "error: missing entry script argument." >&2
  usage >&2
  exit 2
fi

ENTRY_SCRIPT_ARG="$1"
shift

if ! command -v python >/dev/null 2>&1; then
  echo "error: python is required inside container." >&2
  exit 2
fi

if [[ ! -d "${WORKSPACE_DIR}" ]]; then
  echo "error: workspace directory does not exist: ${WORKSPACE_DIR}" >&2
  exit 2
fi
WORKSPACE_REAL="$(realpath -m "${WORKSPACE_DIR}")"

if [[ "${ENTRY_SCRIPT_ARG}" = /* ]]; then
  ENTRY_SCRIPT_WORKSPACE="${ENTRY_SCRIPT_ARG}"
else
  ENTRY_SCRIPT_WORKSPACE="${WORKSPACE_DIR}/${ENTRY_SCRIPT_ARG#./}"
fi
case "${ENTRY_SCRIPT_WORKSPACE}" in
  "${WORKSPACE_DIR}"/*) ;;
  *)
    echo "error: entry script must be inside workspace: ${ENTRY_SCRIPT_WORKSPACE}" >&2
    exit 2
    ;;
esac

if [[ ! -f "${ENTRY_SCRIPT_WORKSPACE}" ]]; then
  echo "error: entry script not found: ${ENTRY_SCRIPT_WORKSPACE}" >&2
  exit 2
fi

TMP_SRC_DIR="$(mktemp -d /tmp/foxclaw-src-XXXXXX)"

cleanup() {
  rm -rf "${TMP_SRC_DIR}"
}
trap cleanup EXIT

if command -v rsync >/dev/null 2>&1; then
  rsync -a \
    --exclude ".git" \
    --exclude ".venv" \
    --exclude "__pycache__" \
    --exclude ".mypy_cache" \
    --exclude ".pytest_cache" \
    --exclude ".ruff_cache" \
    --exclude "firefox-container-artifacts" \
    --exclude "demo-insecure-artifacts" \
    --exclude ".coverage" \
    --exclude "htmlcov" \
    "${WORKSPACE_DIR}/" "${TMP_SRC_DIR}/"
else
  tar -C "${WORKSPACE_DIR}" \
    --exclude ".git" \
    --exclude ".venv" \
    --exclude "__pycache__" \
    --exclude ".mypy_cache" \
    --exclude ".pytest_cache" \
    --exclude ".ruff_cache" \
    --exclude "firefox-container-artifacts" \
    --exclude "demo-insecure-artifacts" \
    --exclude ".coverage" \
    --exclude "htmlcov" \
    -cf - . | tar -C "${TMP_SRC_DIR}" -xf -
fi

ENTRY_REL_PATH="${ENTRY_SCRIPT_WORKSPACE#${WORKSPACE_DIR}/}"
ENTRY_SCRIPT_TMP="${TMP_SRC_DIR}/${ENTRY_REL_PATH}"
if [[ ! -f "${ENTRY_SCRIPT_TMP}" ]]; then
  echo "error: entry script missing in temp workspace: ${ENTRY_REL_PATH}" >&2
  exit 1
fi

cd "${TMP_SRC_DIR}"
# The image installs FoxClaw's Python/build dependencies at build time. Avoid
# runtime pip access here so matrix scans stay offline and deterministic.
export PYTHONPATH="${TMP_SRC_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

if ! python -c 'import cryptography, pydantic, rich, typer, yaml' >/dev/null 2>&1; then
  echo "error: container image is missing FoxClaw Python dependencies; rebuild docker/testbed image." >&2
  exit 1
fi

bash "${ENTRY_SCRIPT_TMP}" --python "python" "$@"
