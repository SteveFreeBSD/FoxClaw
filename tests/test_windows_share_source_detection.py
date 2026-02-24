from __future__ import annotations

import os
from pathlib import Path

from foxclaw.acquire import windows_share


def test_windows_share_source_detection_for_unc_path() -> None:
    assert windows_share.is_windows_share_profile_source(
        Path(r"\\server\forensics\profile.default-release")
    )


def test_windows_share_source_detection_for_smb_mount(monkeypatch, tmp_path: Path) -> None:
    profile_path = tmp_path / "mounted-share" / "profile.default-release"
    if os.name == "nt":
        assert windows_share.is_windows_share_profile_source(profile_path) is False
        return

    monkeypatch.setattr(
        windows_share,
        "_mount_fs_type_for_path",
        lambda _path: "cifs",
    )
    assert windows_share.is_windows_share_profile_source(profile_path)


def test_windows_share_source_detection_for_local_path(monkeypatch, tmp_path: Path) -> None:
    profile_path = tmp_path / "profile.default-release"
    if os.name == "nt":
        assert windows_share.is_windows_share_profile_source(profile_path) is False
        return

    monkeypatch.setattr(
        windows_share,
        "_mount_fs_type_for_path",
        lambda _path: "ext4",
    )
    assert windows_share.is_windows_share_profile_source(profile_path) is False
