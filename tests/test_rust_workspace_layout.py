from __future__ import annotations

import tomllib
from pathlib import Path


def test_rust_workspace_manifest_declares_cli_member() -> None:
    manifest_path = Path("foxclaw-rs/Cargo.toml")
    payload = tomllib.loads(manifest_path.read_text(encoding="utf-8"))

    workspace = payload["workspace"]
    assert "foxclaw-rs-cli" in workspace["members"]


def test_rust_cli_manifest_exists() -> None:
    cli_manifest = Path("foxclaw-rs/foxclaw-rs-cli/Cargo.toml")
    payload = tomllib.loads(cli_manifest.read_text(encoding="utf-8"))

    package = payload["package"]
    assert package["name"] == "foxclaw-rs-cli"
