from importlib.metadata import version

import foxclaw
from foxclaw.cli import app
from typer.testing import CliRunner


def test_package_imports() -> None:
    assert foxclaw.__version__ == version("foxclaw")


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
