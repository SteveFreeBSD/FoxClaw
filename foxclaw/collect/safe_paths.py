"""Safe profile file path helpers shared across collectors."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path


class UnsafeProfilePathError(ValueError):
    """Raised when a candidate profile path is unsafe to read."""


class ProfilePathEscapeError(UnsafeProfilePathError):
    """Raised when a candidate resolves outside the profile root."""


class ProfilePathSymlinkError(UnsafeProfilePathError):
    """Raised when a candidate path traverses a symlink."""


def iter_safe_profile_files(
    profile_dir: Path, relative_paths: Iterable[str]
) -> Iterator[tuple[str, Path]]:
    """Yield resolved profile-file paths after symlink/escape checks."""
    seen: set[str] = set()

    for raw_rel_path in relative_paths:
        rel_path = Path(raw_rel_path)
        rel_key = rel_path.as_posix()
        if rel_key in seen:
            continue
        seen.add(rel_key)

        yield rel_key, resolve_safe_profile_path(profile_dir, rel_path)


def resolve_safe_profile_path(profile_dir: Path, candidate: Path | str) -> Path:
    """Resolve a candidate path and ensure it stays within the profile root."""
    profile_root = profile_dir.expanduser().resolve(strict=False)

    path_obj = Path(candidate).expanduser()
    if not path_obj.is_absolute():
        path_obj = profile_root / path_obj

    _reject_symlink_components(profile_root=profile_root, candidate=path_obj)
    resolved = path_obj.resolve(strict=False)
    if not _is_within_root(resolved, profile_root):
        raise ProfilePathEscapeError(
            f"unsafe profile path escapes profile root: {path_obj} -> {resolved}"
        )
    return resolved


def _reject_symlink_components(*, profile_root: Path, candidate: Path) -> None:
    try:
        relative_candidate = candidate.relative_to(profile_root)
    except ValueError as exc:
        raise ProfilePathEscapeError(
            f"unsafe profile path escapes profile root: {candidate}"
        ) from exc

    current = profile_root
    for token in relative_candidate.parts:
        current = current / token
        if current.is_symlink():
            raise ProfilePathSymlinkError(f"symlinked profile path is not allowed: {current}")


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
