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


def _write_fake_docker(
    path: Path,
    *,
    image_present: bool = True,
    readiness_failures: int = 0,
    logtest_mode: str = "match",
    logtest_failures_before_match: int = 0,
    logtest_sleep_seconds: int = 5,
    alerts_failures: int = 0,
) -> None:
    script = f"""#!/usr/bin/env python3
from __future__ import annotations
import pathlib
import sys
import time

state_dir = pathlib.Path(sys.argv[0]).with_suffix(".state")
state_dir.mkdir(parents=True, exist_ok=True)
log_path = state_dir / "docker-commands.log"
with log_path.open("a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")

def next_count(name: str) -> int:
    counter_path = state_dir / f"{{name}}.count"
    current = int(counter_path.read_text(encoding="utf-8")) if counter_path.exists() else 0
    current += 1
    counter_path.write_text(str(current), encoding="utf-8")
    return current

args = sys.argv[1:]
joined = " ".join(args)
if args[:2] == ["image", "inspect"]:
    raise SystemExit(0 if {image_present!r} else 1)
if args[:1] == ["run"]:
    print("fake-container-id")
    raise SystemExit(0)
if len(args) >= 4 and args[0] == "exec" and args[2] == "test":
    attempt = next_count("readiness")
    raise SystemExit(1 if attempt <= {readiness_failures!r} else 0)
if args[:1] == ["cp"]:
    raise SystemExit(0)
if "wazuh-control" in joined:
    raise SystemExit(0)
if args[:1] == ["exec"] and "wazuh-logtest" in joined:
    attempt = next_count("logtest")
    if {logtest_mode!r} == "timeout":
        time.sleep({logtest_sleep_seconds!r})
        raise SystemExit(0)
    if {logtest_mode!r} == "transient" and attempt <= {logtest_failures_before_match!r}:
        print("**Phase 3: Completed filtering (rules).\\n\\tid: '86600'")
        raise SystemExit(0)
    if {logtest_mode!r} == "nomatch":
        print("**Phase 3: Completed filtering (rules).\\n\\tid: '86600'")
        raise SystemExit(0)
    print("**Phase 3: Completed filtering (rules).\\n\\tid: '100510'\\n**Alert to be generated.")
    raise SystemExit(0)
if "alerts.json" in joined:
    attempt = next_count("alerts")
    if attempt <= {alerts_failures!r}:
        raise SystemExit(1)
    print('189:{{"rule":{{"id":"100510","description":"FoxClaw finding event"}},"data":{{"event_type":"foxclaw.finding","rule_id":"TB-POL-001","severity":"INFO"}}}}')
    raise SystemExit(0)
if "ossec.log" in joined:
    print("ossec line 1\\nossec line 2")
    raise SystemExit(0)
if args[:1] == ["rm"]:
    raise SystemExit(0)
if len(args) >= 3 and args[0] == "exec":
    raise SystemExit(0)
raise SystemExit(0)
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _run_smoke(
    tmp_path: Path,
    *,
    fake_foxclaw: Path,
    fake_docker: Path,
    python_bin: str | None = None,
    timeout_seconds: int = 5,
) -> subprocess.CompletedProcess[str]:
    profile = tmp_path / "profile"
    profile.mkdir(exist_ok=True)
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
        "--docker-cmd",
        f"{sys.executable} {fake_docker}",
        "--container-name",
        "fake-container-id",
        "--timeout-seconds",
        str(timeout_seconds),
    ]
    if python_bin is not None:
        cmd.extend(["--python-bin", python_bin])
    else:
        cmd.extend(["--foxclaw-cmd", f"{sys.executable} {fake_foxclaw}"])
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def test_siem_wazuh_smoke_script_happy_path(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker)

    result = _run_smoke(tmp_path, fake_foxclaw=fake_foxclaw, fake_docker=fake_docker)
    assert result.returncode == 0, result.stdout + result.stderr

    output_dir = tmp_path / "artifacts"
    assert (output_dir / "foxclaw.ndjson").exists()
    assert (output_dir / "wazuh-logtest.txt").read_text(encoding="utf-8")
    assert '"id":"100510"' in (output_dir / "alerts-excerpt.jsonl").read_text(encoding="utf-8")

    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "PASS"
    assert manifest["wazuh_image"] == "wazuh/wazuh-manager:4.14.3"
    assert manifest["top_rule_ids"] == [{"count": 1, "rule_id": "TB-POL-001"}]


def test_siem_wazuh_smoke_script_fails_when_image_missing(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker, image_present=False)

    result = _run_smoke(tmp_path, fake_foxclaw=fake_foxclaw, fake_docker=fake_docker)
    assert result.returncode == 2
    assert "pinned Wazuh image not present locally" in result.stderr

    manifest = json.loads((tmp_path / "artifacts" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "FAIL"
    assert manifest["exit_code"] == 2


def test_siem_wazuh_smoke_script_preserves_python_symlink_path(tmp_path: Path) -> None:
    fake_python_target = tmp_path / "fake_python_target.py"
    fake_python_symlink = tmp_path / "fake_venv_python"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_python_entry(fake_python_target, expected_argv0=str(fake_python_symlink))
    fake_python_symlink.symlink_to(fake_python_target)
    _write_fake_docker(fake_docker)

    result = _run_smoke(
        tmp_path,
        fake_foxclaw=fake_python_target,
        fake_docker=fake_docker,
        python_bin=str(fake_python_symlink),
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_siem_wazuh_smoke_script_retries_readiness_until_success(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker, readiness_failures=2)

    result = _run_smoke(tmp_path, fake_foxclaw=fake_foxclaw, fake_docker=fake_docker)
    assert result.returncode == 0, result.stdout + result.stderr

    commands_log = (fake_docker.with_suffix(".state") / "docker-commands.log").read_text(encoding="utf-8")
    assert commands_log.count("exec fake-container-id test -x /var/ossec/bin/wazuh-logtest") >= 3


def test_siem_wazuh_smoke_script_retries_transient_logtest_and_alerts(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(
        fake_docker,
        logtest_mode="transient",
        logtest_failures_before_match=1,
        alerts_failures=1,
    )

    result = _run_smoke(tmp_path, fake_foxclaw=fake_foxclaw, fake_docker=fake_docker)
    assert result.returncode == 0, result.stdout + result.stderr


def test_siem_wazuh_smoke_script_bounds_logtest_timeout_and_writes_failure_artifacts(tmp_path: Path) -> None:
    fake_foxclaw = tmp_path / "fake_foxclaw.py"
    fake_docker = tmp_path / "fake_docker.py"
    _write_fake_foxclaw(fake_foxclaw)
    _write_fake_docker(fake_docker, logtest_mode="timeout", logtest_sleep_seconds=3)

    result = _run_smoke(
        tmp_path,
        fake_foxclaw=fake_foxclaw,
        fake_docker=fake_docker,
        timeout_seconds=2,
    )
    assert result.returncode == 124
    assert "wazuh-logtest did not match" in result.stderr

    output_dir = tmp_path / "artifacts"
    assert (output_dir / "wazuh-logtest.txt").exists()
    assert (output_dir / "ossec-log-tail.txt").read_text(encoding="utf-8")
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "FAIL"
    assert manifest["exit_code"] == 124
    assert manifest["artifacts"]["ossec_log_tail"].endswith("ossec-log-tail.txt")


def test_soak_runner_declares_siem_wazuh_option_stage_timeout_and_summary() -> None:
    payload = Path("scripts/soak_runner.sh").read_text(encoding="utf-8")
    assert "--siem-wazuh-runs <N>" in payload
    assert "--stage-timeout-seconds <N>" in payload
    assert 'run_step_cmd "${cycle}" "siem_wazuh"' in payload
    assert "soak-summary.json" in payload
    assert "artifact_path" in payload
