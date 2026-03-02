from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "docs_contract_check.py"


def test_docs_contract_check_defaults_to_local_artifacts_report(tmp_path: Path) -> None:
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "INDEX.md").write_text("# Index\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    report_path = tmp_path / "artifacts" / "traceability" / "docs-contract-report.json"
    assert report_path.is_file()
    assert not (tmp_path / "docs" / "traceability" / "docs-contract-report.json").exists()

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["checked_markdown_files"] == 1
    assert payload["issues_count"] == 0


def test_docs_contract_check_honors_explicit_report_out(tmp_path: Path) -> None:
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "INDEX.md").write_text("# Index\nSee `docs/missing.md`\n", encoding="utf-8")

    explicit_report = tmp_path / "docs" / "traceability" / "custom-report.json"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--strict",
            "--report-out",
            str(explicit_report.relative_to(tmp_path)),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    assert result.returncode == 1
    assert explicit_report.is_file()
    payload = json.loads(explicit_report.read_text(encoding="utf-8"))
    assert payload["issues_count"] == 1
    assert payload["issues"][0]["issue_type"] == "missing_path_reference"


def test_docs_contract_check_ignores_node_modules_markdown(tmp_path: Path) -> None:
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "INDEX.md").write_text("# Index\n", encoding="utf-8")

    vendored_dir = tmp_path / "node_modules" / "pkg"
    vendored_dir.mkdir(parents=True, exist_ok=True)
    (vendored_dir / "README.md").write_text(
        "# Vendored Package\n[broken](./missing.md)\nSee `docs/also-missing.md`\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH)],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    report_path = tmp_path / "artifacts" / "traceability" / "docs-contract-report.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["checked_markdown_files"] == 1
    assert payload["issues_count"] == 0
