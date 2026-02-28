#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/generate_sbom.sh [--python <python-bin>] [--dist-dir <path>] [--output <path>]

Generate CycloneDX JSON SBOM from built wheel artifacts using an isolated temp venv.
EOF
}

PYTHON_BIN="python3"
DIST_DIR="dist"
OUTPUT_PATH="sbom.cyclonedx.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python)
      PYTHON_BIN="${2:-}"
      shift 2
      ;;
    --dist-dir)
      DIST_DIR="${2:-}"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="${2:-}"
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

shopt -s nullglob
wheel_candidates=("${DIST_DIR}"/*.whl)
shopt -u nullglob
if [[ "${#wheel_candidates[@]}" -eq 0 ]]; then
  echo "error: no wheel artifacts found under ${DIST_DIR}" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

"${PYTHON_BIN}" -m venv "${tmpdir}/venv"
"${tmpdir}/venv/bin/pip" install --upgrade pip
# Pin a Python-3.14-compatible CycloneDX generator so release SBOM rehearsal
# does not depend on building legacy lxml wheels from source.
"${tmpdir}/venv/bin/pip" install "cyclonedx-bom==7.2.2" "${wheel_candidates[@]}"
"${tmpdir}/venv/bin/cyclonedx-py" environment \
  --output-format JSON \
  --output-file "${OUTPUT_PATH}"

echo "[sbom] generated ${OUTPUT_PATH}"
