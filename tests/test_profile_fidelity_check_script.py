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


def _write_profile(profile_dir: Path, *, with_bad_extensions: bool = False) -> None:
    profile_dir.mkdir(parents=True, exist_ok=True)
    _create_sqlite(profile_dir / "places.sqlite")
    _create_sqlite(profile_dir / "cookies.sqlite")
    (profile_dir / "prefs.js").write_text(
        'user_pref("browser.startup.homepage", "about:home");\n', encoding="utf-8"
    )

    if with_bad_extensions:
        (profile_dir / "extensions.json").write_text(
            json.dumps(
                {
                    "addons": [
                        {
                            "id": "uBlock0@raymondhill.net",
                            "path": "extensions/uBlock0@raymondhill.net.xpi",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )


def test_profile_fidelity_check_passes_for_valid_profile(tmp_path: Path) -> None:
    profile = tmp_path / "profile_ok"
    _write_profile(profile)

    summary = tmp_path / "summary.json"
    command = [
        sys.executable,
        "scripts/profile_fidelity_check.py",
        str(tmp_path),
        "--pattern",
        "profile_*",
        "--min-score",
        "70",
        "--enforce-min-score",
        "--json-out",
        str(summary),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)

    assert result.returncode == 0, result.stderr + result.stdout
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["below_min_count"] == 0
    assert payload["average_score"] >= 70


def test_profile_fidelity_check_fails_for_extension_payload_mismatch(tmp_path: Path) -> None:
    profile = tmp_path / "profile_bad"
    _write_profile(profile, with_bad_extensions=True)

    summary = tmp_path / "summary.json"
    command = [
        sys.executable,
        "scripts/profile_fidelity_check.py",
        str(tmp_path),
        "--pattern",
        "profile_*",
        "--min-score",
        "70",
        "--enforce-min-score",
        "--json-out",
        str(summary),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)

    assert result.returncode == 1
    payload = json.loads(summary.read_text(encoding="utf-8"))
    assert payload["below_min_count"] == 1
    issues = payload["profiles"][0]["issues"]
    assert any("missing payload" in issue for issue in issues)
