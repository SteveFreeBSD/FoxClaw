# Issue: Harden Windows-Share Source Detection Beyond Static Filesystem Allowlist

## Context
Network-share source detection currently depends on a static fs-type allowlist. Unrecognized mount variants can bypass stage-local safety by being treated as local.

## Reproduction / Verification
- Review `_SMB_FILESYSTEM_TYPES` and `is_windows_share_profile_source` logic.
- Add tests for layered/variant mounts and validate fail-closed behavior.

## Acceptance Criteria
- Detection strategy handles layered mount environments safely.
- Tests cover non-cifs SMB-like mount scenarios and fallback behavior.
- No regression for standard local paths.

## Impacted Files
- `foxclaw/acquire/windows_share.py`
- `tests/test_windows_share_source_detection.py`
- `tests/test_cli_exit_codes.py`
