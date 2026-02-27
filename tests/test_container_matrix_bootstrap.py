from __future__ import annotations

import subprocess
from pathlib import Path


def test_container_workspace_exec_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", "scripts/container_workspace_exec.sh"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout


def test_firefox_container_scan_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", "scripts/firefox_container_scan.sh"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout


def test_container_workspace_exec_avoids_runtime_pip_bootstrap() -> None:
    payload = Path("scripts/container_workspace_exec.sh").read_text(encoding="utf-8")
    assert 'pip install -e ".[dev]"' not in payload
    assert "python -m venv" not in payload
    assert 'export PYTHONPATH="${TMP_SRC_DIR}${PYTHONPATH:+:${PYTHONPATH}}"' in payload
    assert "import cryptography, pydantic, rich, typer, yaml" in payload
    assert (
        "error: container image is missing FoxClaw Python dependencies; rebuild docker/testbed image."
        in payload
    )
    assert 'bash "${ENTRY_SCRIPT_TMP}" --python "python" "$@"' in payload


def test_testbed_dockerfile_preinstalls_python_requirements_from_pyproject() -> None:
    payload = Path("docker/testbed/Dockerfile").read_text(encoding="utf-8")
    assert "COPY pyproject.toml README.md /tmp/foxclaw-build/" in payload
    assert 'data["build-system"]["requires"]' in payload
    assert 'data["project"]["dependencies"]' in payload
    assert 'data["project"]["optional-dependencies"]["dev"]' in payload
    assert "python -m pip install --no-cache-dir -r /tmp/foxclaw-build/requirements.txt" in payload
