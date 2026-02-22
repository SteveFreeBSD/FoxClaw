from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def _create_sqlite(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()


def _write_profile(profile_dir: Path) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)
    _create_sqlite(profile_dir / "places.sqlite")
    _create_sqlite(profile_dir / "cookies.sqlite")
    (profile_dir / "prefs.js").write_text(
        'user_pref("browser.startup.homepage", "about:home");\n',
        encoding="utf-8",
    )


def _write_fake_firefox(path: Path, *, delete_cookies: bool) -> None:
    script = [
        "#!/usr/bin/env python3",
        "from __future__ import annotations",
        "import pathlib",
        "import sys",
        "args = sys.argv[1:]",
        "for idx, arg in enumerate(args):",
        "    if arg == '--profile' and idx + 1 < len(args):",
        "        profile = pathlib.Path(args[idx + 1])",
        "        if " + ("True" if delete_cookies else "False") + ":",
        "            try:",
        "                (profile / 'cookies.sqlite').unlink()",
        "            except FileNotFoundError:",
        "                pass",
        "        break",
        "raise SystemExit(0)",
    ]
    path.write_text("\n".join(script) + "\n", encoding="utf-8")
    path.chmod(0o755)


def test_profile_launch_gate_passes_with_fake_firefox(tmp_path: Path) -> None:
    profile = tmp_path / "profile_ok"
    _write_profile(profile)

    fake_firefox = tmp_path / "fake-firefox-ok"
    _write_fake_firefox(fake_firefox, delete_cookies=False)

    summary = tmp_path / "summary.json"
    command = [
        sys.executable,
        "scripts/profile_launch_gate.py",
        str(tmp_path),
        "--pattern",
        "profile_*",
        "--firefox-bin",
        str(fake_firefox),
        "--min-post-score",
        "70",
        "--enforce",
        "--json-out",
        str(summary),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)

    assert result.returncode == 0, result.stderr + result.stdout
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["profiles_evaluated"] == 1
    assert payload["profiles_failed"] == 0
    assert payload["profiles_survived"] == 1


def test_profile_launch_gate_fails_when_firefox_missing_and_enforced(tmp_path: Path) -> None:
    profile = tmp_path / "profile_ok"
    _write_profile(profile)

    missing_firefox = tmp_path / "does-not-exist-firefox"
    command = [
        sys.executable,
        "scripts/profile_launch_gate.py",
        str(tmp_path),
        "--pattern",
        "profile_*",
        "--firefox-bin",
        str(missing_firefox),
        "--enforce",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)

    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert "SKIP: Firefox binary" in combined


def test_profile_launch_gate_fails_when_launch_deletes_artifacts(tmp_path: Path) -> None:
    profile = tmp_path / "profile_bad"
    _write_profile(profile)

    fake_firefox = tmp_path / "fake-firefox-destructive"
    _write_fake_firefox(fake_firefox, delete_cookies=True)

    summary = tmp_path / "summary.json"
    command = [
        sys.executable,
        "scripts/profile_launch_gate.py",
        str(tmp_path),
        "--pattern",
        "profile_*",
        "--firefox-bin",
        str(fake_firefox),
        "--min-post-score",
        "70",
        "--enforce",
        "--json-out",
        str(summary),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)

    assert result.returncode == 1
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["profiles_failed"] == 1
    issues = payload["results"][0]["issues"]
    assert any("cookies.sqlite" in issue for issue in issues)
