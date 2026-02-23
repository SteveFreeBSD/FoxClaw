"""Read-only filesystem permission checks for sensitive Firefox files."""

from __future__ import annotations

import stat
from pathlib import Path

from foxclaw.collect.safe_paths import iter_safe_profile_files
from foxclaw.models import FilePermEvidence

SENSITIVE_FILE_NAMES: tuple[str, ...] = (
    "logins.json",
    "key4.db",
    "cert9.db",
    "cookies.sqlite",
    "places.sqlite",
    "extensions.json",
    "prefs.js",
    "user.js",
)

SQLITE_AUX_NAMES: tuple[str, ...] = (
    "cookies.sqlite-wal",
    "cookies.sqlite-shm",
    "places.sqlite-wal",
    "places.sqlite-shm",
)


def collect_file_permissions(profile_dir: Path) -> list[FilePermEvidence]:
    """Collect permission evidence for sensitive files present in a profile."""
    candidate_names = sorted({*SENSITIVE_FILE_NAMES, *SQLITE_AUX_NAMES})

    evidence: list[FilePermEvidence] = []
    for _rel_path, path in iter_safe_profile_files(profile_dir, candidate_names):
        if not path.exists() or not path.is_file():
            continue

        try:
            file_stat = path.stat()
        except OSError:
            continue

        mode_bits = stat.S_IMODE(file_stat.st_mode)
        group_readable = bool(mode_bits & stat.S_IRGRP)
        group_writable = bool(mode_bits & stat.S_IWGRP)
        world_readable = bool(mode_bits & stat.S_IROTH)
        world_writable = bool(mode_bits & stat.S_IWOTH)
        needs_hardening = (
            group_readable or group_writable or world_readable or world_writable
        )

        evidence.append(
            FilePermEvidence(
                path=str(path),
                mode=f"{mode_bits:04o}",
                owner_uid=getattr(file_stat, "st_uid", None),
                owner_gid=getattr(file_stat, "st_gid", None),
                group_readable=group_readable,
                group_writable=group_writable,
                world_readable=world_readable,
                world_writable=world_writable,
                recommended_chmod=f"chmod 600 {path}" if needs_hardening else None,
            )
        )
    return evidence
