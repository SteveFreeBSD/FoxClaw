import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def test_live_orchestration_cli_success(tmp_path: Path):
    """Test that `foxclaw live` successfully fetches intel and scans."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "foxclaw",
            "live",
            "--source",
            "foxclaw-amo=tests/fixtures/intel/amo_extension_intel.v1.json",
            "--profile",
            "tests/fixtures/firefox_profile",
            "--ruleset",
            "foxclaw/rulesets/balanced.yml",
            "--intel-store-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )
    
    # The default firefox_profile has 1 HIGH finding (FC-FILE-001) so we expect exit code 2
    assert result.returncode == 2, result.stderr
    # `rich` wraps text, so strip all whitespace for reliable matching
    normalized_stdout = result.stdout.replace("\n", "").replace(" ", "")
    assert "Synchronizingintelligencesources" in normalized_stdout
    assert "Syncsuccessful" in normalized_stdout
    assert "Executingdeterministicscan" in normalized_stdout
    assert "ScanSummary" in normalized_stdout

def test_live_orchestration_cli_sync_failure(tmp_path: Path):
    """Test that `foxclaw live` fails closed if sync fails."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "foxclaw",
            "live",
            "--source",
            "foxclaw-amo=does_not_exist.json",
            "--profile",
            "tests/fixtures/firefox_profile",
            "--ruleset",
            "foxclaw/rulesets/balanced.yml",
            "--intel-store-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )
    
    # 1 indicates operational error (sync failed)
    assert result.returncode == 1, result.stderr
    normalized_stdout = result.stdout.replace("\n", "").replace(" ", "")
    assert "Synchronizingintelligencesources" in normalized_stdout
    assert "Syncfailed:unabletoreadsource" in normalized_stdout
    assert "Abortingscanduetosyncfailure" in normalized_stdout
