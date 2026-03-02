#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="${1:-/mnt/firefox-profiles}"

if [[ ! -d "${SOURCE_ROOT}" ]]; then
  echo "error: source root does not exist: ${SOURCE_ROOT}" >&2
  exit 1
fi

if ! command -v findmnt >/dev/null 2>&1; then
  echo "error: findmnt is required for windows-share preflight" >&2
  exit 1
fi

# Trigger systemd automount before checking filesystem type.
if ! ls -1 "${SOURCE_ROOT}" >/dev/null 2>&1; then
  echo "error: source root is not readable: ${SOURCE_ROOT}" >&2
  exit 1
fi

fs_types_raw="$(findmnt -n -T "${SOURCE_ROOT}" -o FSTYPE 2>/dev/null || true)"
fs_types="$(echo "${fs_types_raw}" | tr '\n' ' ' | xargs)"
supported_fs_pattern='^(cifs|smb3|smbfs|fuse\.smbnetfs)$'
if ! echo "${fs_types_raw}" | grep -Eq "${supported_fs_pattern}"; then
  echo "error: source root is not a supported SMB mount: ${SOURCE_ROOT} (fstype=${fs_types:-unknown})" >&2
  exit 1
fi

profiles_count="$(
  find "${SOURCE_ROOT}" -mindepth 1 -maxdepth 1 -type d ! -name '.*' | wc -l | tr -d ' '
)"
if [[ "${profiles_count}" -eq 0 ]]; then
  echo "error: no visible profile directories found under ${SOURCE_ROOT}" >&2
  exit 1
fi

echo "[windows-share-preflight] source_root=${SOURCE_ROOT}"
echo "[windows-share-preflight] fstype=${fs_types}"
echo "[windows-share-preflight] profiles_count=${profiles_count}"
