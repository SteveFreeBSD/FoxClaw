"""Firefox profile discovery and deterministic selection."""

from __future__ import annotations

import configparser
import math
import os
from pathlib import Path

from pydantic import BaseModel, Field

_PROFILE_LOCK_FILES = ("parent.lock", "lock")
_DEFAULT_RELEASE_SUFFIX = ".default-release"


class FirefoxProfile(BaseModel):
    """Discovered Firefox profile and selection metadata."""

    profile_id: str
    name: str
    path: Path
    is_relative: bool
    default_flag: bool
    lock_detected: bool
    lock_files: list[str] = Field(default_factory=list)
    places_size_bytes: int = 0
    directory_mtime: float = 0.0
    suffix_score: float = 0.0
    default_score: float = 0.0
    places_score: float = 0.0
    mtime_score: float = 0.0
    total_score: float = 0.0
    selected: bool = False
    selection_reason: str | None = None


class ProfileDiscoveryReport(BaseModel):
    """Full discovery report for profile selection."""

    searched_dirs: list[Path] = Field(default_factory=list)
    base_dir: Path | None = None
    profiles_ini: Path | None = None
    profiles: list[FirefoxProfile] = Field(default_factory=list)
    selected_profile_id: str | None = None
    selection_reason: str | None = None


def get_profile_search_dirs(
    *, home: Path | None = None, xdg_config_home: Path | None = None
) -> list[Path]:
    """Return deterministic search dirs for Firefox profile discovery."""
    resolved_home = (home or Path.home()).expanduser()
    if xdg_config_home is None:
        xdg_env = os.environ.get("XDG_CONFIG_HOME")
        if xdg_env:
            xdg_config_home = Path(xdg_env).expanduser()

    candidates: list[Path] = []
    if xdg_config_home is not None:
        candidates.append(xdg_config_home / "mozilla" / "firefox")
    candidates.append(resolved_home / ".config" / "mozilla" / "firefox")
    candidates.append(resolved_home / ".mozilla" / "firefox")

    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        normalized = candidate.expanduser()
        if normalized not in seen:
            deduped.append(normalized)
            seen.add(normalized)
    return deduped


def discover_profiles(
    *, home: Path | None = None, xdg_config_home: Path | None = None
) -> ProfileDiscoveryReport:
    """Discover profiles from `profiles.ini` and deterministically pick one."""
    search_dirs = get_profile_search_dirs(home=home, xdg_config_home=xdg_config_home)
    report = ProfileDiscoveryReport(searched_dirs=search_dirs)

    profiles_ini, base_dir = _find_profiles_ini(search_dirs)
    if profiles_ini is None or base_dir is None:
        return report

    report.base_dir = base_dir
    report.profiles_ini = profiles_ini
    report.profiles = _parse_profiles_ini(base_dir=base_dir, profiles_ini=profiles_ini)
    if not report.profiles:
        return report

    _score_profiles(report.profiles)
    selected = _select_profile(report.profiles)
    if selected is None:
        return report

    selected.selected = True
    if selected.lock_detected:
        selected.selection_reason = (
            "Selected due to active lock file(s): "
            f"{', '.join(selected.lock_files)}."
        )
    else:
        selected.selection_reason = (
            "Selected by deterministic score "
            f"(suffix={selected.suffix_score:.2f}, "
            f"default={selected.default_score:.2f}, "
            f"places={selected.places_score:.2f}, "
            f"mtime={selected.mtime_score:.2f})."
        )
    report.selected_profile_id = selected.profile_id
    report.selection_reason = selected.selection_reason
    return report


def _find_profiles_ini(search_dirs: list[Path]) -> tuple[Path | None, Path | None]:
    for base_dir in search_dirs:
        ini_path = base_dir / "profiles.ini"
        if ini_path.is_file():
            return ini_path, base_dir
    return None, None


def _parse_profiles_ini(*, base_dir: Path, profiles_ini: Path) -> list[FirefoxProfile]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(profiles_ini, encoding="utf-8")

    profiles: list[FirefoxProfile] = []
    for section in parser.sections():
        if not section.startswith("Profile"):
            continue

        path_value = parser.get(section, "Path", fallback="").strip()
        if not path_value:
            continue

        is_relative = parser.get(section, "IsRelative", fallback="1").strip() == "1"
        raw_path = Path(path_value)
        resolved_path = (base_dir / raw_path) if is_relative else raw_path.expanduser()
        default_flag = parser.get(section, "Default", fallback="0").strip() == "1"
        lock_files = _detect_lock_files(resolved_path)
        places_size = _stat_file_size(resolved_path / "places.sqlite")
        dir_mtime = _stat_directory_mtime(resolved_path)

        profiles.append(
            FirefoxProfile(
                profile_id=section,
                name=parser.get(section, "Name", fallback=section),
                path=resolved_path,
                is_relative=is_relative,
                default_flag=default_flag,
                lock_detected=bool(lock_files),
                lock_files=lock_files,
                places_size_bytes=places_size,
                directory_mtime=dir_mtime,
            )
        )
    return profiles


def _detect_lock_files(profile_dir: Path) -> list[str]:
    lock_files: list[str] = []
    for lock_name in _PROFILE_LOCK_FILES:
        if (profile_dir / lock_name).exists():
            lock_files.append(lock_name)
    return lock_files


def _stat_file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _stat_directory_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _score_profiles(profiles: list[FirefoxProfile]) -> None:
    max_places = max((profile.places_size_bytes for profile in profiles), default=0)
    mtimes = [profile.directory_mtime for profile in profiles if profile.directory_mtime > 0]
    min_mtime = min(mtimes, default=0.0)
    max_mtime = max(mtimes, default=0.0)

    for profile in profiles:
        profile.suffix_score = (
            35.0 if profile.path.name.endswith(_DEFAULT_RELEASE_SUFFIX) else 0.0
        )
        profile.default_score = 25.0 if profile.default_flag else 0.0
        profile.places_score = (
            25.0 * (profile.places_size_bytes / max_places) if max_places > 0 else 0.0
        )
        if max_mtime <= 0:
            profile.mtime_score = 0.0
        elif math.isclose(max_mtime, min_mtime):
            profile.mtime_score = 15.0
        else:
            profile.mtime_score = (
                15.0
                * (profile.directory_mtime - min_mtime)
                / (max_mtime - min_mtime)
            )
        profile.total_score = (
            profile.suffix_score
            + profile.default_score
            + profile.places_score
            + profile.mtime_score
        )


def _select_profile(profiles: list[FirefoxProfile]) -> FirefoxProfile | None:
    if not profiles:
        return None

    locked_profiles = [profile for profile in profiles if profile.lock_detected]
    ranked_pool = locked_profiles if locked_profiles else profiles
    ranked = sorted(ranked_pool, key=_profile_sort_key)
    return ranked[0] if ranked else None


def _profile_sort_key(profile: FirefoxProfile) -> tuple[float, int, int, int, float, str]:
    return (
        -profile.total_score,
        -int(profile.default_flag),
        -int(profile.path.name.endswith(_DEFAULT_RELEASE_SUFFIX)),
        -profile.places_size_bytes,
        -profile.directory_mtime,
        str(profile.path),
    )
