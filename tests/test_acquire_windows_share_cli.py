from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path

from foxclaw.cli import app
from typer.testing import CliRunner


def _create_sqlite(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()


def _write_source_profile(root: Path, *, with_lock_marker: bool = False, weak_key4: bool = False) -> Path:
    profile = root / "source_profile"
    profile.mkdir(parents=True, exist_ok=True)
    (profile / "prefs.js").write_text('user_pref("browser.startup.homepage", "about:home");\n', encoding="utf-8")
    _create_sqlite(profile / "places.sqlite")
    _create_sqlite(profile / "cookies.sqlite")
    if weak_key4:
        (profile / "key4.db").write_text("secret", encoding="utf-8")
        (profile / "key4.db").chmod(0o644)
    if with_lock_marker:
        (profile / "parent.lock").write_text("locked\n", encoding="utf-8")
    return profile


def _write_fake_foxclaw(path: Path, *, exit_code: int) -> None:
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

json_out.write_text(json.dumps({{"summary": {{"findings_high_count": 1}}}}), encoding='utf-8')
sarif_out.write_text(json.dumps({{"version": "2.1.0", "runs": []}}), encoding='utf-8')
snapshot_out.write_text(json.dumps({{"schema_version": "1.0.0"}}), encoding='utf-8')
raise SystemExit({exit_code})
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def test_acquire_windows_share_scan_passes_through_high_finding_exit_code(tmp_path: Path) -> None:
    source_profile = _write_source_profile(tmp_path)

    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    _write_fake_foxclaw(fake_foxclaw, exit_code=2)

    output_dir = tmp_path / "artifacts"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--output-dir",
            str(output_dir),
            "--foxclaw-cmd",
            f"{sys.executable} {fake_foxclaw}",
        ],
    )

    assert result.exit_code == 2, result.stdout
    manifest = json.loads((output_dir / "stage-manifest.json").read_text(encoding="utf-8"))
    assert manifest["scan"]["exit_code"] == 2
    assert manifest["scan"]["status"] == "PASS"


def test_acquire_windows_share_scan_can_normalize_high_findings_exit_code(tmp_path: Path) -> None:
    source_profile = _write_source_profile(tmp_path)

    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    _write_fake_foxclaw(fake_foxclaw, exit_code=2)

    output_dir = tmp_path / "artifacts"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--output-dir",
            str(output_dir),
            "--treat-high-findings-as-success",
            "--foxclaw-cmd",
            f"{sys.executable} {fake_foxclaw}",
        ],
    )

    assert result.exit_code == 0, result.stdout


def test_acquire_windows_share_scan_fails_closed_on_lock_marker(tmp_path: Path) -> None:
    source_profile = _write_source_profile(tmp_path, with_lock_marker=True)

    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    _write_fake_foxclaw(fake_foxclaw, exit_code=0)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--foxclaw-cmd",
            f"{sys.executable} {fake_foxclaw}",
        ],
    )

    assert result.exit_code == 1
    assert "active-profile lock markers detected" in (result.stdout + result.stderr)


def test_acquire_windows_share_scan_detects_real_high_finding(tmp_path: Path) -> None:
    source_profile = _write_source_profile(tmp_path, weak_key4=True)

    ruleset = tmp_path / "rules.yml"
    ruleset.write_text(
        "\n".join(
            [
                "name: share-lane-test",
                "version: 1.0.0",
                "rules:",
                "  - id: SHARE-HIGH-001",
                "    title: key4 strict perms",
                "    severity: HIGH",
                "    category: filesystem",
                "    check:",
                "      file_perm_strict:",
                "        key: key4",
                "    rationale: test",
                "    recommendation: test",
                "    confidence: high",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    output_dir = tmp_path / "artifacts"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--ruleset",
            str(ruleset),
            "--output-dir",
            str(output_dir),
            "--foxclaw-cmd",
            f"{sys.executable} -m foxclaw",
        ],
    )

    assert result.exit_code == 2, result.stdout
    payload = json.loads((output_dir / "foxclaw.json").read_text(encoding="utf-8"))
    assert payload["summary"]["findings_high_count"] >= 1
    assert "SHARE-HIGH-001" in payload["high_findings"]


def test_acquire_windows_share_scan_can_target_mounted_share_path(tmp_path: Path) -> None:
    source_profile = _write_source_profile(tmp_path)
    mounted_path = tmp_path / "mounted-share" / source_profile.name
    mounted_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_profile, mounted_path)

    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    _write_fake_foxclaw(fake_foxclaw, exit_code=0)

    output_dir = tmp_path / "artifacts"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(mounted_path),
            "--output-dir",
            str(output_dir),
            "--foxclaw-cmd",
            f"{sys.executable} {fake_foxclaw}",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert (output_dir / "stage-manifest.json").exists()


def test_acquire_windows_share_scan_rejects_staging_root_filesystem_root(tmp_path: Path) -> None:
    source_profile = _write_source_profile(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--staging-root",
            "/",
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "staging root cannot be filesystem root" in (result.stdout + result.stderr)


def test_acquire_windows_share_scan_rejects_staging_root_home_directory(tmp_path: Path) -> None:
    source_profile = _write_source_profile(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--staging-root",
            "~",
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "staging root cannot be home directory root" in (result.stdout + result.stderr)


def test_acquire_windows_share_scan_rejects_staging_root_inside_source_profile(tmp_path: Path) -> None:
    source_profile = _write_source_profile(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--staging-root",
            str(source_profile / "nested-staging-root"),
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "staging root cannot be inside source profile" in (result.stdout + result.stderr)


def test_acquire_windows_share_scan_rejects_source_profile_inside_staging_root(tmp_path: Path) -> None:
    staging_root = tmp_path / "staging-root"
    source_profile = _write_source_profile(staging_root)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            str(source_profile),
            "--staging-root",
            str(staging_root),
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "source profile cannot be inside staging root" in (result.stdout + result.stderr)


def test_acquire_windows_share_scan_rejects_unc_source_on_non_windows() -> None:
    if os.name == "nt":
        return

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "acquire",
            "windows-share-scan",
            "--source-profile",
            r"\\server\forensics\profile.default-release",
            "--dry-run",
        ],
    )

    assert result.exit_code == 1
    assert "UNC source profile paths are not directly accessible on this platform" in (
        result.stdout + result.stderr
    )
