from __future__ import annotations

import os
from pathlib import Path

from foxclaw.cli import app
from foxclaw.profiles import discover_profiles
from typer.testing import CliRunner


def _write_profiles_ini(base_dir: Path, content: str) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "profiles.ini").write_text(content, encoding="utf-8")


def _create_profile(
    base_dir: Path,
    relative_path: str,
    *,
    places_size: int = 0,
    lock_name: str | None = None,
    mtime: int | None = None,
) -> None:
    profile_dir = base_dir / relative_path
    profile_dir.mkdir(parents=True, exist_ok=True)
    if places_size > 0:
        (profile_dir / "places.sqlite").write_bytes(b"x" * places_size)
    if lock_name:
        (profile_dir / lock_name).write_text("", encoding="utf-8")
    if mtime is not None:
        os.utime(profile_dir, (mtime, mtime))


def test_profile_selection_prefers_locked_profile(tmp_path: Path) -> None:
    home = tmp_path / "home"
    base_dir = home / ".mozilla" / "firefox"
    _write_profiles_ini(
        base_dir,
        """[Profile0]
Name=release
IsRelative=1
Path=Profiles/aaa.default-release
Default=1

[Profile1]
Name=work
IsRelative=1
Path=Profiles/bbb.default
""",
    )

    _create_profile(base_dir, "Profiles/aaa.default-release", places_size=4096, mtime=100)
    _create_profile(
        base_dir,
        "Profiles/bbb.default",
        places_size=128,
        lock_name="parent.lock",
        mtime=10,
    )

    report = discover_profiles(home=home, xdg_config_home=tmp_path / "missing-xdg")

    assert report.selected_profile_id == "Profile1"
    assert report.selection_reason is not None
    assert "lock" in report.selection_reason.lower()

    selected = next(profile for profile in report.profiles if profile.selected)
    assert selected.profile_id == "Profile1"
    assert selected.lock_detected is True


def test_profile_selection_uses_default_release_suffix_when_other_signals_equal(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    base_dir = home / ".mozilla" / "firefox"
    _write_profiles_ini(
        base_dir,
        """[Profile0]
Name=release
IsRelative=1
Path=Profiles/ccc.default-release

[Profile1]
Name=generic
IsRelative=1
Path=Profiles/ddd.default
""",
    )

    _create_profile(base_dir, "Profiles/ccc.default-release", places_size=1024, mtime=200)
    _create_profile(base_dir, "Profiles/ddd.default", places_size=1024, mtime=200)

    report = discover_profiles(home=home, xdg_config_home=tmp_path / "missing-xdg")

    assert report.selected_profile_id == "Profile0"
    selected = next(profile for profile in report.profiles if profile.selected)
    assert selected.path.name.endswith(".default-release")
    assert selected.suffix_score > 0
    assert report.selection_reason is not None
    assert "score" in report.selection_reason.lower()


def test_profile_discovery_prefers_xdg_profiles_ini_location(tmp_path: Path) -> None:
    home = tmp_path / "home"
    xdg = tmp_path / "xdg"

    xdg_base = xdg / "mozilla" / "firefox"
    config_base = home / ".config" / "mozilla" / "firefox"
    legacy_base = home / ".mozilla" / "firefox"

    _write_profiles_ini(
        xdg_base,
        """[Profile0]
Name=xdg
IsRelative=1
Path=Profiles/xdg.default-release
""",
    )
    _create_profile(xdg_base, "Profiles/xdg.default-release", places_size=10, mtime=300)

    _write_profiles_ini(
        config_base,
        """[Profile0]
Name=config
IsRelative=1
Path=Profiles/config.default
""",
    )
    _create_profile(config_base, "Profiles/config.default", places_size=10, mtime=200)

    _write_profiles_ini(
        legacy_base,
        """[Profile0]
Name=legacy
IsRelative=1
Path=Profiles/legacy.default
""",
    )
    _create_profile(legacy_base, "Profiles/legacy.default", places_size=10, mtime=100)

    report = discover_profiles(home=home, xdg_config_home=xdg)

    assert report.base_dir == xdg_base
    assert report.profiles_ini == xdg_base / "profiles.ini"
    assert report.selected_profile_id == "Profile0"
    assert any(profile.path.name == "xdg.default-release" for profile in report.profiles)


def test_profiles_list_cli_prints_selection_reason(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    base_dir = home / ".mozilla" / "firefox"

    _write_profiles_ini(
        base_dir,
        """[Profile0]
Name=main
IsRelative=1
Path=Profiles/main.default-release
Default=1
""",
    )
    _create_profile(base_dir, "Profiles/main.default-release", places_size=512, mtime=500)

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    runner = CliRunner()
    result = runner.invoke(app, ["profiles", "list"])

    assert result.exit_code == 0
    assert "Selected profile:" in result.stdout
    assert "Selection reason:" in result.stdout
