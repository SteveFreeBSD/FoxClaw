from typer.testing import CliRunner

import foxclaw
from foxclaw.cli import app


def test_package_imports() -> None:
    assert foxclaw.__version__ == "0.1.0"


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
