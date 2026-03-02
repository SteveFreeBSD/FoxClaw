from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _read_key_value_file(path: Path) -> dict[str, str]:
    payload: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key] = value
    return payload


def test_soak_runner_marks_operator_stop_as_interrupted(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    make_started_file = tmp_path / "make-started"
    output_root = tmp_path / "soak-output"

    _write_executable(
        fake_bin / "docker",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
printf 'unexpected docker args: %s\\n' "$*" >&2
exit 1
""",
    )
    _write_executable(
        fake_bin / "timeout",
        """#!/usr/bin/env bash
set -euo pipefail
shift 2
exec "$@"
""",
    )
    _write_executable(
        fake_bin / "make",
        """#!/usr/bin/env bash
set -euo pipefail
printf 'started\\n' >"${FAKE_MAKE_STARTED_FILE}"
trap 'exit 143' TERM INT
sleep 30
exit 0
""",
    )

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_MAKE_STARTED_FILE"] = str(make_started_file)

    process = subprocess.Popen(
        [
            "bash",
            "scripts/soak_runner.sh",
            "--duration-hours",
            "1",
            "--max-cycles",
            "1",
            "--stage-timeout-seconds",
            "60",
            "--integration-runs",
            "1",
            "--snapshot-runs",
            "1",
            "--synth-count",
            "1",
            "--fuzz-count",
            "1",
            "--adversary-runs",
            "0",
            "--siem-wazuh-runs",
            "0",
            "--matrix-runs",
            "0",
            "--label",
            "ws82-interrupt-test",
            "--output-root",
            str(output_root),
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )

    deadline = time.time() + 10
    while time.time() < deadline:
        if make_started_file.exists():
            break
        if process.poll() is not None:
            break
        time.sleep(0.1)

    assert make_started_file.exists(), (
        (process.stdout.read() if process.stdout is not None else "")
        + (process.stderr.read() if process.stderr is not None else "")
    )

    os.killpg(process.pid, signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=20)
    assert process.returncode == 0, stdout + stderr

    run_dirs = sorted(output_root.iterdir())
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]

    summary = _read_key_value_file(run_dir / "summary.txt")
    assert summary["overall_status"] == "INTERRUPTED"
    assert summary["stop_reason"] == "signal"
    assert summary["steps_total"] == "1"
    assert summary["steps_passed"] == "0"
    assert summary["steps_failed"] == "0"
    assert summary["steps_interrupted"] == "1"
    assert summary["failed_artifact_paths"] == "-"
    assert summary["interrupted_artifact_paths"] == "-"

    results_lines = (run_dir / "results.tsv").read_text(encoding="utf-8").splitlines()
    assert len(results_lines) == 2
    fields = results_lines[1].split("\t")
    assert fields[1] == "integration"
    assert fields[4] == "INTERRUPTED"
    assert fields[9] == "-"

    soak_summary = json.loads((run_dir / "soak-summary.json").read_text(encoding="utf-8"))
    assert soak_summary["schema_version"] == "1.1.0"
    assert soak_summary["overall_status"] == "INTERRUPTED"
    assert soak_summary["steps_total"] == 1
    assert soak_summary["steps_passed"] == 0
    assert soak_summary["steps_failed"] == 0
    assert soak_summary["steps_interrupted"] == 1
    assert soak_summary["failed_artifact_paths"] == []
    assert soak_summary["interrupted_artifact_paths"] == []
    assert soak_summary["stage_counts"] == {
        "integration": {"fail": 0, "interrupted": 1, "pass": 0},
    }
