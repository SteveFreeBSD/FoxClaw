from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write_fake_foxclaw(path: Path, *, exit_code: int = 0) -> None:
    script = f"""#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import sys

args = sys.argv[1:]
ndjson_out = None
for idx, arg in enumerate(args):
    if arg == "--ndjson-out" and idx + 1 < len(args):
        ndjson_out = pathlib.Path(args[idx + 1])

if ndjson_out is None:
    raise SystemExit(9)

ndjson_out.parent.mkdir(parents=True, exist_ok=True)
lines = [
    {{"schema_version":"1.0.0","timestamp":"2025-01-01T00:00:00Z","event_id":"finding-id","event_type":"foxclaw.finding","host":{{"id":"host-01","name":"host-01"}},"profile":{{"profile_id":"manual","name":"profile_baseline"}},"rule_id":"TB-POL-001","severity":"INFO","title":"finding","message":"finding","scan_id":"scan-1"}},
    {{"schema_version":"1.0.0","timestamp":"2025-01-01T00:00:00Z","event_id":"summary-id","event_type":"foxclaw.scan.summary","host":{{"id":"host-01","name":"host-01"}},"profile":{{"profile_id":"manual","name":"profile_baseline"}},"severity":"INFO","title":"summary","message":"summary","scan_id":"scan-1","findings_total":1,"findings_high_count":0,"findings_medium_count":0,"findings_info_count":1,"findings_suppressed_count":0}}
]
ndjson_out.write_text("\\n".join(json.dumps(item, separators=(',', ':')) for item in lines) + "\\n", encoding="utf-8")
raise SystemExit({exit_code})
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _write_fake_python_entry(path: Path, *, expected_argv0: str, exit_code: int = 0) -> None:
    script = f"""#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import sys

if pathlib.Path(sys.argv[0]).resolve() != pathlib.Path({expected_argv0!r}).resolve() or sys.argv[0] != {expected_argv0!r}:
    raise SystemExit(17)

args = sys.argv[1:]
ndjson_out = None
for idx, arg in enumerate(args):
    if arg == "--ndjson-out" and idx + 1 < len(args):
        ndjson_out = pathlib.Path(args[idx + 1])

if ndjson_out is None:
    raise SystemExit(9)

ndjson_out.parent.mkdir(parents=True, exist_ok=True)
lines = [
    {{"schema_version":"1.0.0","timestamp":"2025-01-01T00:00:00Z","event_id":"finding-id","event_type":"foxclaw.finding","host":{{"id":"host-01","name":"host-01"}},"profile":{{"profile_id":"manual","name":"profile_baseline"}},"rule_id":"TB-POL-001","severity":"INFO","title":"finding","message":"finding","scan_id":"scan-1"}},
    {{"schema_version":"1.0.0","timestamp":"2025-01-01T00:00:00Z","event_id":"summary-id","event_type":"foxclaw.scan.summary","host":{{"id":"host-01","name":"host-01"}},"profile":{{"profile_id":"manual","name":"profile_baseline"}},"severity":"INFO","title":"summary","message":"summary","scan_id":"scan-1","findings_total":1,"findings_high_count":0,"findings_medium_count":0,"findings_info_count":1,"findings_suppressed_count":0}}
]
ndjson_out.write_text("\\n".join(json.dumps(item, separators=(',', ':')) for item in lines) + "\\n", encoding="utf-8")
raise SystemExit({exit_code})
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _write_fake_docker(path: Path, *, image_present: bool = True, logtest_matches: bool = True) -> None:
    script = f"""#!/usr/bin/env python3
from __future__ import annotations
import pathlib
import sys

state_dir = pathlib.Path(sys.argv[0]).with_suffix(".state")
state_dir.mkdir(parents=True, exist_ok=True)
log_path = state_dir / "docker-commands.log"
with log_path.open("a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")

args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    raise SystemExit(0 if {image_present!r} else 1)
if args[:1] == ["run"]:
    print("fake-container-id")
    raise SystemExit(0)
if len(args) >= 4 and args[0] == "exec" and args[2] == "test":
    raise SystemExit(0)
if args[:1] == ["cp"]:
    raise SystemExit(0)
if len(args) >= 3 and args[0] == "exec" and args[2] == "/var/ossec/bin/wazuh-control":
    raise SystemExit(0)
if args[:1] == ["exec"] and "wazuh-logtest" in " ".join(args):
    if {logtest_matches!r}:
        print("**Phase 3: Completed filtering (rules).\\n\\tid: '100510'\\n**Alert to be generated.")
    else:
        print("**Phase 3: Completed filtering (rules).\\n\\tid: '86600'")
    raise SystemExit(0)
if args[:1] == ["rm"]:
    raise SystemExit(0)
if "alerts.json" in " ".join(args):
    print('189:{{"rule":{{"id":"100510","description":"FoxClaw finding event"}},"data":{{"event_type":"foxclaw.finding","rule_id":"TB-POL-001","severity":"INFO"}}}}')
    raise SystemExit(0)
if len(args) >= 3 and args[0] == "exec":
    raise SystemExit(0)
raise SystemExit(0)
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def test_siem_wazuh_smoke_script_happy_path(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)

    profile = tmp_path / "profile"
    profile.mkdir()
    ruleset = tmp_path / "rules.yml"
    ruleset.write_text("name: test\nversion: 1.0.0\nrules: []\n", encoding="utf-8")

    output_dir = tmp_path / "artifacts"
    cmd = [
        sys.executable,
        "scripts/siem_wazuh_smoke.py",
        "--output-dir",
        str(output_dir),
        "--profile",
        str(profile),
        "--ruleset",
        str(ruleset),
        "--foxclaw-cmd",
        f"{sys.executable} {fake_foxclaw}",
        "--docker-cmd",
        f"{sys.executable} {fake_docker}",
        "--container-name",
        "fake-container-id",
    ]

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (output_dir / "foxclaw.ndjson").exists()
    assert (output_dir / "wazuh-logtest.txt").read_text(encoding="utf-8")
    alerts_excerpt = (output_dir / "alerts-excerpt.jsonl").read_text(encoding="utf-8")
    assert '"id":"100510"' in alerts_excerpt
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["wazuh_image"] == "wazuh/wazuh-manager:4.14.3"


def test_siem_wazuh_smoke_script_fails_when_image_missing(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker, image_present=False)

    profile = tmp_path / "profile"
    profile.mkdir()
    ruleset = tmp_path / "rules.yml"
    ruleset.write_text("name: test\nversion: 1.0.0\nrules: []\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/siem_wazuh_smoke.py",
            "--output-dir",
            str(tmp_path / "artifacts"),
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--foxclaw-cmd",
            f"{sys.executable} {fake_foxclaw}",
            "--docker-cmd",
            f"{sys.executable} {fake_docker}",
            "--container-name",
            "fake-container-id",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "pinned Wazuh image not present locally" in result.stderr


def test_siem_wazuh_smoke_script_preserves_python_symlink_path(tmp_path: Path) -> None:
    fake_python_target = tmp_path / "fake_python_target.py"
    fake_python_symlink = tmp_path / "fake_venv_python"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_python_entry(fake_python_target, expected_argv0=str(fake_python_symlink))
    fake_python_symlink.symlink_to(fake_python_target)
    _write_fake_docker(fake_docker)

    profile = tmp_path / "profile"
    profile.mkdir()
    ruleset = tmp_path / "rules.yml"
    ruleset.write_text("name: test\nversion: 1.0.0\nrules: []\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/siem_wazuh_smoke.py",
            "--output-dir",
            str(tmp_path / "artifacts"),
            "--profile",
            str(profile),
            "--ruleset",
            str(ruleset),
            "--python-bin",
            str(fake_python_symlink),
            "--docker-cmd",
            f"{sys.executable} {fake_docker}",
            "--container-name",
            "fake-container-id",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_soak_runner_declares_siem_wazuh_option_and_stage() -> None:
    payload = Path("scripts/soak_runner.sh").read_text(encoding="utf-8")
    assert "--siem-wazuh-runs <N>" in payload
    assert 'run_step_cmd "${cycle}" "siem_wazuh"' in payload
