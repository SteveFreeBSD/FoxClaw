from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

_GOLDEN_STAGE_MANIFEST = (
    Path(__file__).resolve().parent / "fixtures" / "windows_share" / "stage-manifest.json"
)


def _write_fake_profile(root: Path, *, with_lock_marker: bool = False) -> Path:
    profile = root / "source_profile"
    profile.mkdir(parents=True, exist_ok=True)
    (profile / "prefs.js").write_text(
        'user_pref("browser.startup.homepage", "about:home");\n', encoding="utf-8"
    )
    (profile / "cookies.sqlite").write_bytes(b"sqlite-binary")
    if with_lock_marker:
        (profile / "parent.lock").write_text("locked\n", encoding="utf-8")
    return profile


def _set_file_mtime(path: Path, *, epoch_seconds: int) -> None:
    os.utime(path, (epoch_seconds, epoch_seconds))


def _write_fake_foxclaw(path: Path, *, exit_code: int = 0) -> None:
    script = f"""#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import sys

args = sys.argv[1:]
json_out = None
sarif_out = None
snapshot_out = None

for idx, arg in enumerate(args):
    if arg == '--output' and idx + 1 < len(args):
        json_out = pathlib.Path(args[idx + 1])
    elif arg == '--sarif-out' and idx + 1 < len(args):
        sarif_out = pathlib.Path(args[idx + 1])
    elif arg == '--snapshot-out' and idx + 1 < len(args):
        snapshot_out = pathlib.Path(args[idx + 1])

if json_out is None or sarif_out is None or snapshot_out is None:
    raise SystemExit(9)

json_out.parent.mkdir(parents=True, exist_ok=True)
sarif_out.parent.mkdir(parents=True, exist_ok=True)
snapshot_out.parent.mkdir(parents=True, exist_ok=True)

json_out.write_text(json.dumps({{"summary": {{"findings_high_count": 0}}}}), encoding='utf-8')
sarif_out.write_text(json.dumps({{"version": "2.1.0", "runs": []}}), encoding='utf-8')
snapshot_out.write_text(json.dumps({{"schema_version": "1.0.0"}}), encoding='utf-8')
raise SystemExit({exit_code})
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def test_windows_share_scan_manifest_records_per_file_sha256_entries(tmp_path: Path) -> None:
    source_profile = _write_fake_profile(tmp_path)
    _set_file_mtime(source_profile / "prefs.js", epoch_seconds=1735689600)
    _set_file_mtime(source_profile / "cookies.sqlite", epoch_seconds=1735689600)

    output_dir = tmp_path / "artifacts"
    cmd = [
        sys.executable,
        "scripts/windows_share_scan.py",
        "--source-profile",
        str(source_profile),
        "--snapshot-id",
        "unit-test-snapshot",
        "--staging-root",
        str(tmp_path / "staging"),
        "--output-dir",
        str(output_dir),
        "--dry-run",
    ]

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

    manifest = json.loads((output_dir / "stage-manifest.json").read_text(encoding="utf-8"))
    golden = json.loads(_GOLDEN_STAGE_MANIFEST.read_text(encoding="utf-8"))

    assert manifest["copy"] == golden["copy"]
    assert manifest["files"] == golden["files"]


def test_windows_share_scan_stages_locally_and_propagates_high_findings(tmp_path: Path) -> None:
    source_profile = _write_fake_profile(tmp_path)

    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    _write_fake_foxclaw(fake_foxclaw, exit_code=2)

    output_dir = tmp_path / "artifacts"
    cmd = [
        sys.executable,
        "scripts/windows_share_scan.py",
        "--source-profile",
        str(source_profile),
        "--snapshot-id",
        "unit-test-snapshot",
        "--staging-root",
        str(tmp_path / "staging"),
        "--output-dir",
        str(output_dir),
        "--foxclaw-cmd",
        f"{sys.executable} {fake_foxclaw}",
    ]

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert result.returncode == 2, result.stdout + result.stderr

    manifest = json.loads((output_dir / "stage-manifest.json").read_text(encoding="utf-8"))
    assert manifest["copy"]["files"] >= 2
    assert manifest["scan"]["exit_code"] == 2
    assert manifest["scan"]["status"] == "PASS"

    staged_profile = Path(manifest["staged_profile"])
    staged_prefs = staged_profile / "prefs.js"
    assert staged_prefs.exists()

    mode = staged_prefs.stat().st_mode
    assert mode & stat.S_IWUSR == 0


def test_windows_share_scan_can_treat_high_findings_as_success(tmp_path: Path) -> None:
    source_profile = _write_fake_profile(tmp_path)

    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    _write_fake_foxclaw(fake_foxclaw, exit_code=2)

    output_dir = tmp_path / "artifacts"
    cmd = [
        sys.executable,
        "scripts/windows_share_scan.py",
        "--source-profile",
        str(source_profile),
        "--output-dir",
        str(output_dir),
        "--treat-high-findings-as-success",
        "--foxclaw-cmd",
        f"{sys.executable} {fake_foxclaw}",
    ]

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

    manifest = json.loads((output_dir / "stage-manifest.json").read_text(encoding="utf-8"))
    assert manifest["scan"]["exit_code"] == 2
    assert manifest["scan"]["status"] == "PASS"


def test_windows_share_scan_fails_when_active_lock_marker_present(tmp_path: Path) -> None:
    source_profile = _write_fake_profile(tmp_path, with_lock_marker=True)

    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    _write_fake_foxclaw(fake_foxclaw)

    cmd = [
        sys.executable,
        "scripts/windows_share_scan.py",
        "--source-profile",
        str(source_profile),
        "--foxclaw-cmd",
        f"{sys.executable} {fake_foxclaw}",
    ]

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert result.returncode == 1
    assert "active-profile lock markers detected" in (result.stdout + result.stderr)


def test_windows_share_scan_allows_lock_marker_with_override(tmp_path: Path) -> None:
    source_profile = _write_fake_profile(tmp_path, with_lock_marker=True)

    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    _write_fake_foxclaw(fake_foxclaw)

    output_dir = tmp_path / "artifacts"
    cmd = [
        sys.executable,
        "scripts/windows_share_scan.py",
        "--source-profile",
        str(source_profile),
        "--output-dir",
        str(output_dir),
        "--allow-active-profile",
        "--foxclaw-cmd",
        f"{sys.executable} {fake_foxclaw}",
    ]

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

    manifest = json.loads((output_dir / "stage-manifest.json").read_text(encoding="utf-8"))
    assert "parent.lock" in manifest["source_lock_markers"]
    assert manifest["scan"]["status"] == "PASS"
