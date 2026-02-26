from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _write_fake_findmnt(path: Path) -> None:
    path.write_text(
        "#!/usr/bin/env bash\n"
        "if [[ \"$*\" == *\"-o FSTYPE\"* ]]; then\n"
        "  printf 'autofs\\ncifs\\n'\n"
        "  exit 0\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_windows_share_preflight_accepts_autofs_plus_cifs(tmp_path: Path) -> None:
    source_root = tmp_path / "profiles"
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "profile-a").mkdir(parents=True, exist_ok=True)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    _write_fake_findmnt(fake_bin / "findmnt")

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"

    result = subprocess.run(
        ["bash", "scripts/windows_share_preflight.sh", str(source_root)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "[windows-share-preflight] fstype=autofs cifs" in result.stdout
    assert "[windows-share-preflight] profiles_count=1" in result.stdout
