from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def _write_fake_findmnt(path: Path, fs_types: tuple[str, ...]) -> None:
    rendered_fs_types = "\\n".join(fs_types)
    path.write_text(
        "#!/usr/bin/env bash\n"
        "if [[ \"$*\" == *\"-o FSTYPE\"* ]]; then\n"
        f"  printf '{rendered_fs_types}\\n'\n"
        "  exit 0\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run_preflight(tmp_path: Path, fs_types: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    source_root = tmp_path / "profiles"
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "profile-a").mkdir(parents=True, exist_ok=True)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    _write_fake_findmnt(fake_bin / "findmnt", fs_types)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"

    return subprocess.run(
        ["bash", "scripts/windows_share_preflight.sh", str(source_root)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.mark.parametrize(
    ("fs_types", "expected_fstype"),
    [
        (("autofs", "cifs"), "autofs cifs"),
        (("autofs", "smb3"), "autofs smb3"),
        (("autofs", "smbfs"), "autofs smbfs"),
        (("autofs", "fuse.smbnetfs"), "autofs fuse.smbnetfs"),
    ],
)
def test_windows_share_preflight_accepts_supported_smb_mounts(
    tmp_path: Path,
    fs_types: tuple[str, ...],
    expected_fstype: str,
) -> None:
    result = _run_preflight(tmp_path, fs_types)

    assert result.returncode == 0, result.stderr + result.stdout
    assert f"[windows-share-preflight] fstype={expected_fstype}" in result.stdout
    assert "[windows-share-preflight] profiles_count=1" in result.stdout


def test_windows_share_preflight_rejects_unsupported_mount_type(tmp_path: Path) -> None:
    result = _run_preflight(tmp_path, ("autofs", "nfs"))

    assert result.returncode == 1
    assert "error: source root is not a supported SMB mount" in result.stderr
    assert "fstype=autofs nfs" in result.stderr
